# version: 20260407.02
BEGIN {
    # The cmd variable must be passed
    if (cmd == "") exit 1

    cleanup_counter = 0
    # Trigger the run program if a repeated IP occurs within this interval
    retryperiod = 600
    # Trigger the external command asynchronously to prevent external scripts from blocking awk's event loop
    run_external_format = "%s ssh ban %s &"
}

# [Core Trick] Hack to get the current timestamp in POSIX awk
# Standard POSIX awk does not have a systime() function. However, srand() uses the current time as the seed by default,
# and the specification requires it to return the previous seed value. Calling it twice in a row gets the current Epoch timestamp with no overhead.
function get_time() {
    srand()
    return srand()
}

# Validate IPv4 format
function is_valid_ipv4(ip,   arr, i, n) {
    n = split(ip, arr, ".")
  
    # Must have 4 segments
    if (n != 4) return 0
    
    for (i = 1; i <= 4; i++) {
        # Must be purely numeric, and in the range of 0-255
        if (arr[i] !~ /^[0-9]+$/ || arr[i] + 0 > 255 || arr[i] + 0 < 0) {
            return 0
        }
    }
    return 1
}

# Validate IPv6 format
function is_valid_ipv6(ip,   arr, n, i, double_colon_count, tmp_ip) {
    # 1. Basic filtering: length (shortest :: is 2, longest is 39), invalid character filtering
    if (length(ip) < 2 || length(ip) > 39) return 0
    if (ip !~ /^[0-9a-fA-F:]+$/) return 0
    
    # 2. Exclude malformed formats with three or more consecutive colons (e.g., :::)
    if (ip ~ /:::/) return 0
    
    # 3. Count the occurrences of the zero-compression flag "::" (a valid IPv6 can have at most 1)
    tmp_ip = ip
    double_colon_count = gsub(/::/, "", tmp_ip)
    if (double_colon_count > 1) return 0
   
    # 4. Cannot start or end with a single colon (unless it is ::)
    if (ip ~ /^:[^:]/ || ip ~ /[^:]:$/) return 0

    # 5. Split by colon, validate each segment
    n = split(ip, arr, ":")
    
    # A full IPv6 has 8 segments (7 colons). If there is a "::", the number of segments must be less than 8; otherwise, it must strictly equal 8
    if (n > 8) return 0
    if (double_colon_count == 0 && n != 8) return 0
    
    for (i = 1; i <= n; i++) {
        # If it is not an empty segment (an empty segment represents part of "::"), the length cannot exceed 4 hexadecimal characters
        if (length(arr[i]) > 0 && length(arr[i]) > 4) {
            return 0
        }
    }
    
    return 1
}

# Clear expired records from memory to prevent awk memory leaks caused by long-term operation
function cleanup_seen(now,   k) {
    for (k in seen) {
        if (now - seen[k] > retryperiod) {
            delete seen[k]
        }
    }
}

# Process and record the IP
function process_ip(ip,   now) {
    now = get_time()

    if (ip in seen) {
        # Record found and within retryperiod seconds
        if (now - seen[ip] <= retryperiod) {
            callback = sprintf(run_external_format, cmd, ip)
            print(callback)
            system(callback)
            
            # Remove from records immediately after triggering to avoid generating a large number of storm alerts from the same IP within 1 minute
            delete seen[ip]
        } else {
            # Exceeds retryperiod seconds, reset the timer
            seen[ip] = now
        }
    } else {
        # First appearance, record the time
        seen[ip] = now
    }

    # Amortize cleanup overhead: perform an expired cache cleanup every 50 valid IPs extracted
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
    # Group 1: Match features ending with rhost=<ip>
    # Covering rules: authentication failure;.*rhost=<ip>
    # =================================================================
    if (match($0, /ssh.+authentication failure;.*rhost=[0-9a-fA-F:\.]+/)) {
        # Secondarily locate rhost=... directly within the entire line
        match($0, /rhost=[0-9a-fA-F:\.]+/)
        # RSTART+6 to skip "rhost="
        ip = substr($0, RSTART + 6, RLENGTH - 6)
      
        check_and_process(ip)
    }

    # =================================================================
    # Group 2: Match features containing from <ip> (Failed password, Invalid user, invalid format)
    # Covering rules:
    # 1. Failed password for .* from <ip>
    # 2. Invalid user .* from <ip>
    # 3. Connection from <ip> port [0-9]*: invalid format
    # =================================================================
    else if (match($0, /ssh.+(Failed password|Invalid user|Connection).* from [0-9a-fA-F:\.]+/)) {
        match($0, /from [0-9a-fA-F:\.]+/)
        # RSTART+5 to skip "from "
        ip = substr($0, RSTART + 5, RLENGTH - 5)
        check_and_process(ip)
    }

    # =================================================================
    # Group 3: Match disconnections during the Preauth phase
    # Covering rules:
    # 1. Disconnected from .* <ip> .*preauth
    # 2. Disconnecting .* <ip> .*preauth
    # 3. Received disconnect from <ip> .*preauth
    # 4. Unable to negotiate with <ip> .*preauth
    # 5. Connection (reset|closed) by <ip> port .*preauth
    # 6. Connection (reset|closed) by (authenticating|invalid) user .* <ip> port
    # =================================================================
    else if (match($0, /ssh.+(Disconnected|Disconnecting|Received disconnect|Unable to negotiate|Connection closed by|Connection reset by).* [0-9a-fA-F:\.]+ .*preauth/)) {
        substr_match = substr($0, RSTART, RLENGTH)
        # [Advanced Trick] Since the IP is wrapped in the middle of variable-length .*, forcibly extracting it with regex is error-prone.
        # The safest method: split the extracted log segment into words by spaces, and iterate through them to check which word is a valid IP.
        split(substr_match, words, " ")
        for (i in words) {
            if (is_valid_ipv4(words[i]) || is_valid_ipv6(words[i])) {
                process_ip(words[i])
                break # Break out of the loop immediately after finding the attacker's source IP
            }
        }
    }

    # =================================================================
    # Group 4: Match authentication timeouts
    # Covering rules: Timeout before authentication for <ip>
    # =================================================================
    else if (match($0, /ssh.+Timeout before authentication for [0-9a-fA-F:\.]+/)) {
        match($0, /for [0-9a-fA-F:\.]+/)
        # RSTART+4 to skip "for "
        ip = substr($0, RSTART + 4, RLENGTH - 4)
        check_and_process(ip)
    }
}