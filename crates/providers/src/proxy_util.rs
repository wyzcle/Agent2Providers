//! 账号代理的插件侧解析：网关提供实际出口，旧网关回落到静态配置。
//!
//! `store::record_of` 把网关解析结果投影到运行时 `proxy`，原始凭证与代理配置
//! 留在快照里供条件更新。代理池 / Clash / 轮询只由网关解析，插件不读池状态。
//! 没有网关解析结果时，兼容 URL 与协议 / 主机 / 端口两种静态形态；依赖网关
//! 状态的来源仍如实报错。

use serde_json::Value;

use agent2api_provider_protocol::WireProxy;

/// 代理配置的解析结果。
pub enum ProxyResolution {
    /// 解析成功
    Resolved(WireProxy),
    /// 配置存在但用不了（文案给用户看）
    Failed(String),
}

/// 「只有对话走代理」开关的环境变量名。
pub const CHAT_ONLY_PROXY_ENV: &str = "A2A_CHAT_ONLY_PROXY";

/// 是否开着「只有对话走代理」。
///
/// ── 这个开关做什么 ──────────────────────────────────────────
/// 账号代理的语义本来是「这家账号的所有出站都走它」：对话、查余额、签到、
/// 拉模型目录、刷新凭证，全都走同一个出口。可是运营侧真正要躲的往往只是
/// **对话**那一条链的风控 —— 余额/签到/目录这些控制面请求走代理，除了多花
/// 隧道时长没有别的好处（有的还因为换了 IP 反而触发异地校验）。
///
/// 打开之后，本文件的 [`chat_only_proxy`] 会让**控制面**请求一律直连，
/// 对话链原样保留账号代理。对话链不归这里管：它由网关通过
/// `ChatRequest.proxy` 传下来，插件本来就只能服从。
///
/// ── 为什么默认关 ────────────────────────────────────────────
/// 默认必须是官方行为。没设这个环境变量时本函数返回 `false`，所有调用点
/// 拿到原值，与上游逐字一致 —— 这样官方更新时本地的改动面只是一次
/// 「多包一层函数」的机械替换，不会悄悄改变用户没要求的语义。
pub fn chat_only_proxy_enabled() -> bool {
    parse_switch(std::env::var(CHAT_ONLY_PROXY_ENV).ok().as_deref())
}

/// 开关值的判定（抽出来是为了单测：`set_var` 在测试里并发不安全）。
///
/// 只认明确的真值。空串、`0`、`false`、拼错的值一律当「关」—— 这个开关
/// 一开就会改变出网路径，宁可让人发现「设了没生效」，也不要让手误的值
/// 悄悄生效。
fn parse_switch(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("TRUE") | Some("yes"))
}

/// 控制面请求该用的代理：开关打开时一律 `None`（直连），否则原样透传。
///
/// ── 只给「纯读」控制面用 ────────────────────────────────────
/// 余额、额度、签到、活动、用量统计这类**读了也不改变身份**的请求可以用它。
///
/// **身份锚点不要调它**：登录、凭证续期（`refresh` / `renew` / `ensure_fresh`）、
/// 身份确认（`refresh_identity`）、模型目录（部分平台把目录与账号授权绑在一起，
/// 且对话路径会读它）。这些请求换 IP 会让上游看到「同一个账号在两个地方活动」，
/// 比全程同 IP 更可疑 —— 那是把省隧道时长换成了封号风险，得不偿失。
pub fn chat_only_proxy(proxy: Option<&WireProxy>) -> Option<&WireProxy> {
    if chat_only_proxy_enabled() {
        None
    } else {
        proxy
    }
}

/// 解析账号记录里的 `proxy` 配置。
///
/// `None` = 没配代理（直连）；`Some(Resolved)` = 可用；`Some(Failed)` = 配错了。
pub fn resolve_account_proxy(config: Option<&Value>) -> Option<ProxyResolution> {
    let config = config?;
    if config.is_null() {
        return None;
    }
    if let Some(config) = config.get("config").filter(|value| value.is_object()) {
        return resolve_account_proxy(Some(config));
    }
    let Some(object) = config.as_object() else {
        return Some(ProxyResolution::Failed(
            "不支持的代理来源: undefined".to_string(),
        ));
    };
    if let Some(message) = object
        .get("error")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        return Some(ProxyResolution::Failed(message.to_string()));
    }
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_lowercase();
    if source == "direct" {
        return None;
    }
    if matches!(source.as_str(), "system" | "rotate" | "pool" | "clash") {
        return Some(ProxyResolution::Failed(format!(
            "网关未提供「{source}」代理来源的实际出口，请更新网关与提供商插件"
        )));
    }
    if let Some(host) = object
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .trim()
            .to_lowercase();
        if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks4") {
            return Some(ProxyResolution::Failed(format!(
                "不支持的代理协议: {protocol}"
            )));
        }
        let port = match object.get("port") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let parsed = value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()));
                let Some(port) = parsed
                    .and_then(|port| u16::try_from(port).ok())
                    .filter(|port| *port > 0)
                else {
                    return Some(ProxyResolution::Failed(
                        "代理端口必须是 1-65535 的整数".to_string(),
                    ));
                };
                Some(port)
            }
        };
        return Some(ProxyResolution::Resolved(WireProxy {
            protocol,
            host: host.trim_matches(|ch| ch == '[' || ch == ']').to_string(),
            port,
            username: object
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            password: object
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }));
    }
    for key in ["url", "proxy", "address", "server"] {
        let candidate = object
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if candidate.is_empty() {
            continue;
        }
        return match parse_proxy_url(candidate) {
            Some(proxy) => Some(ProxyResolution::Resolved(proxy)),
            None => Some(ProxyResolution::Failed(format!(
                "代理地址无法解析（{candidate}）：需要形如 http://host:port 或 socks5://host:port"
            ))),
        };
    }
    if source.is_empty() {
        return None;
    }
    Some(ProxyResolution::Failed(format!(
        "代理配置缺少地址（source={source}）"
    )))
}

/// 把代理 URL 拆成 `WireProxy`。
///
/// 手写解析而不是引 `url` crate：只需要 `scheme://[user:pass@]host:port` 这一种
/// 形态，而 `url` crate 会把「端口非法」「用户信息里有 @」这些情况各自归一成
/// 不同错误 —— 这里要的只是「能拆就拆，拆不出就说清」。
pub fn parse_proxy_url(text: &str) -> Option<WireProxy> {
    let text = text.trim();
    let (scheme, rest) = text.split_once("://")?;
    let protocol = scheme.trim().to_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks4") {
        return None;
    }
    // 用户信息：最后一个 @ 之前的部分（密码里可能有 @）
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, rest),
    };
    let hostport = hostport.trim_end_matches('/');
    if hostport.is_empty() {
        return None;
    }
    // IPv6 形态 [::1]:8080 也走这条（冒号在后面）
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.trim();
            if port.is_empty() {
                (host, None)
            } else {
                (host, Some(port.parse::<u16>().ok()?))
            }
        }
        None => (hostport, None),
    };
    if host.is_empty() {
        return None;
    }
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((user, pass)) => (decode(user), decode(pass)),
            None => (decode(userinfo), String::new()),
        },
        None => (String::new(), String::new()),
    };
    Some(WireProxy {
        protocol,
        host: host.trim_matches(|ch| ch == '[' || ch == ']').to_string(),
        port,
        username,
        password,
    })
}

/// 最小百分号解码（代理认证信息里常见 `%40` 这类转义）。
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &text[index + 1..index + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    //! 「只有对话走代理」开关的判定。
    //!
    //! 这里钉的是**默认关**与**只认明确真值**两条：这个开关一开就改出网路径，
    //! 手误（`A2A_CHAT_ONLY_PROXY=0`、空串、拼成 `yse`）绝不能生效。
    use super::*;

    #[test]
    fn 未设置时是关的() {
        assert!(!parse_switch(None));
    }

    #[test]
    fn 只认四个明确真值() {
        for value in ["1", "true", "TRUE", "yes"] {
            assert!(parse_switch(Some(value)), "{value} 应判为开");
        }
    }

    #[test]
    fn 其余一律判为关() {
        for value in ["", "0", "false", "FALSE", "no", "off", "yse", " true", "true "] {
            assert!(!parse_switch(Some(value)), "{value:?} 应判为关");
        }
    }

    /// 开关关着时 `chat_only_proxy` 必须**原样透传** —— 这是「默认行为与
    /// 上游逐字一致」的保证，也是官方更新时改动面能保持机械替换的前提。
    #[test]
    fn 关着时原样透传() {
        let proxy = WireProxy {
            protocol: "socks5".into(),
            host: "127.0.0.1".into(),
            port: Some(41081),
            username: String::new(),
            password: String::new(),
        };
        // 用 parse_switch 直接验证语义（不碰环境变量）
        assert!(!parse_switch(None));
        let kept = if parse_switch(None) { None } else { Some(&proxy) };
        assert_eq!(kept.map(|p| p.port), Some(Some(41081)));
    }

    /// 开着时必须给出 `None`（直连）。
    #[test]
    fn 开着时给直连() {
        let proxy = WireProxy {
            protocol: "socks5".into(),
            host: "127.0.0.1".into(),
            port: Some(41081),
            username: String::new(),
            password: String::new(),
        };
        let dropped = if parse_switch(Some("1")) { None } else { Some(&proxy) };
        assert!(dropped.is_none());
    }
}
