# version: 20260407.02
BEGIN {
    # 必须传入 cmd 变量
    if (cmd == "") exit 1

    cleanup_counter = 0
    # 重复IP在此间隔内则触发运行程序
    retryperiod = 600
    # 异步触发外部命令，防止外部脚本阻塞 awk 的事件循环
    run_external_format = "%s ssh ban %s &"
}

# [核心技巧] POSIX awk 获取当前时间戳的 Hack
# 标准 POSIX awk 没有 systime() 函数。但 srand() 默认使用当前时间作为种子，
# 且规范要求它返回上一次的种子值。连续调用两次即可无开销获取当前 Epoch 时间戳。
function get_time() {
    srand()
    return srand()
}

# 校验 IPv4 格式合法性
function is_valid_ipv4(ip,   arr, i, n) {
    n = split(ip, arr, ".")
    # 必须是4段
    if (n != 4) return 0
    
    for (i = 1; i <= 4; i++) {
        # 必须是纯数字，且范围在 0-255 之间
        if (arr[i] !~ /^[0-9]+$/ || arr[i] + 0 > 255 || arr[i] + 0 < 0) {
            return 0
        }
    }
    return 1
}

# 校验 IPv6 格式合法性
function is_valid_ipv6(ip,   arr, n, i, double_colon_count, tmp_ip) {
    # 1. 基础过滤：长度(最短 :: 为2，最长 39)、非法字符过滤
    if (length(ip) < 2 || length(ip) > 39) return 0
    if (ip !~ /^[0-9a-fA-F:]+$/) return 0
    
    # 2. 排除连续三个冒号及以上的畸形格式 (如 :::)
    if (ip ~ /:::/) return 0
    
    # 3. 统计零压缩标志 "::" 出现的次数 (合法 IPv6 最多只能有 1 个)
    tmp_ip = ip
    double_colon_count = gsub(/::/, "", tmp_ip)
    if (double_colon_count > 1) return 0
    
    # 4. 不能以单个冒号开头或结尾（除非是 ::）
    if (ip ~ /^:[^:]/ || ip ~ /[^:]:$/) return 0

    # 5. 按冒号分割，验证每一段
    n = split(ip, arr, ":")
    
    # IPv6 全写为 8 段 (7个冒号)。如果有 "::"，段数必然小于 8；否则必须严格等于 8
    if (n > 8) return 0
    if (double_colon_count == 0 && n != 8) return 0
    
    for (i = 1; i <= n; i++) {
        # 如果不是空段（空段代表 "::" 的一部分），则长度不能超过4个十六进制字符
        if (length(arr[i]) > 0 && length(arr[i]) > 4) {
            return 0
        }
    }
    
    return 1
}

# 清理内存中的过期记录，防止长期运行导致 awk 内存泄漏
function cleanup_seen(now,   k) {
    for (k in seen) {
        if (now - seen[k] > retryperiod) {
            delete seen[k]
        }
    }
}

# 处理并记录 IP
function process_ip(ip,   now) {
    now = get_time()

    if (ip in seen) {
        # 发现记录且在 retryperiod 秒内
        if (now - seen[ip] <= retryperiod) {
            callback = sprintf(run_external_format, cmd, ip)
            print(callback)
            system(callback)
            
            # 触发后立即从记录中移除，避免在 1 分钟内同一 IP 产生大量风暴告警
            delete seen[ip]
        } else {
            # 超过 retryperiod 秒，重置计时器
            seen[ip] = now
        }
    } else {
        # 首次出现，记录时间
        seen[ip] = now
    }

    # 摊销清理开销：每提取 50 个有效 IP，执行一次过期缓存清理
    cleanup_counter++
    if (cleanup_counter > 50) {
        cleanup_seen(now)
        cleanup_counter = 0
    }
}

function check_and_process(ip) {
    if (is_valid_ipv4(ip) || is_valid_ipv6(ip)) {
        process_ip(ip)
    }
}

{
    # =================================================================
    # 组 1: 匹配以 rhost=<ip> 结尾的特征
    # 涵盖规则: authentication failure;.*rhost=<ip>
    # =================================================================
    if (match($0, /ssh.+authentication failure;.*rhost=[0-9a-fA-F:\.]+/)) {
        # 直接在整行中二次定位 rhost=... 
        match($0, /rhost=[0-9a-fA-F:\.]+/)
        # RSTART+6 跳过 "rhost="
        ip = substr($0, RSTART + 6, RLENGTH - 6)
        check_and_process(ip)
    }

    # =================================================================
    # 组 2: 匹配包含 from <ip> 的特征 (密码失败、无效用户、格式错误)
    # 涵盖规则: 
    # 1. Failed password for .* from <ip>
    # 2. Invalid user .* from <ip>
    # 3. Connection from <ip> port [0-9]*: invalid format
    # =================================================================
    else if (match($0, /ssh.+(Failed password|Invalid user|Connection).* from [0-9a-fA-F:\.]+/)) {
        match($0, /from [0-9a-fA-F:\.]+/)
        # RSTART+5 跳过 "from "
        ip = substr($0, RSTART + 5, RLENGTH - 5)
        check_and_process(ip)
    }

    # =================================================================
    # 组 3: 匹配 Preauth 阶段的断开连接
    # 涵盖规则:
    # 1. Disconnected from .* <ip> .*preauth
    # 2. Disconnecting .* <ip> .*preauth
    # 3. Received disconnect from <ip> .*preauth
    # 4. Unable to negotiate with <ip> .*preauth
    # 5. Connection (reset|closed) by <ip> port .*preauth
    # 6. Connection (reset|closed) by (authenticating|invalid) user .* <ip> port
    # =================================================================
    else if (match($0, /ssh.+(Disconnected|Disconnecting|Received disconnect|Unable to negotiate|Connection closed by|Connection reset by).* [0-9a-fA-F:\.]+ .*preauth/)) {
        substr_match = substr($0, RSTART, RLENGTH)
        # [高级技巧] 因为这里 IP 被包裹在不定长的 .* 中间，强行用正则截取容易出错。
        # 最稳妥的方法：将截取出的日志段按空格打散成词，直接遍历校验哪个词是合法 IP。
        split(substr_match, words, " ")
        for (i in words) {
            if (is_valid_ipv4(words[i]) || is_valid_ipv6(words[i])) {
                process_ip(words[i])
                break # 找到攻击源 IP 后立即跳出循环
            }
        }
    }

    # =================================================================
    # 组 4: 匹配认证超时
    # 涵盖规则: Timeout before authentication for <ip>
    # =================================================================
    else if (match($0, /ssh.+Timeout before authentication for [0-9a-fA-F:\.]+/)) {
        match($0, /for [0-9a-fA-F:\.]+/)
        # RSTART+4 跳过 "for "
        ip = substr($0, RSTART + 4, RLENGTH - 4)
        check_and_process(ip)
    }
}
