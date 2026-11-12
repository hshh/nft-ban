# version: 20261113.01

BEGIN {
    # The cmd variable must be passed
    if (cmd == "") exit 1

    # Pass variables externally via -v. If not provided, set default values.
    if (retryperiod == "") retryperiod = 600
    if (max_hits == "") max_hits = 2
    
    # Force numeric types to prevent string comparison pitfalls
    retryperiod += 0
    max_hits += 0
    
    # Used to record the timestamp of the last full cache cleanup.
    last_cleanup = 0
    
    # Trigger external commands asynchronously to prevent external scripts from blocking awk's event loop.
    run_external_format = "%s ssh ban %s &"
}

# Validate IPv4 format
function is_valid_ipv4(ip,   arr, i, n) {
    # Use "[.]" (length > 1) so all awk engines strictly treat it as a literal dot regex
    n = split(ip, arr, "[.]")
  
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
    
    # A full IPv6 has 8 segments (7 colons).
    # If there is a "::", the number of segments must be less than 8;
    # otherwise, it must strictly equal 8
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
    # The traversal time complexity remains O(N), but since the invocation frequency is drastically reduced, the overhead is negligible.
    for (k in seen_time) {
        if (now - seen_time[k] > retryperiod) {
            delete seen_time[k]
            delete seen_count[k]
        }
    }
}

# Process and record the IP
function process_ip(ip,   now, callback) {
    now = systime()
    
    # Initialize the global cleanup timestamp
    if (last_cleanup == 0) last_cleanup = now

    # Logic 1: Determine if the IP is a new record, or has already exceeded the retryperiod window.
    if (!(ip in seen_time) || (now - seen_time[ip] > retryperiod)) {
        # Reset the current IP's lifecycle and counter
        seen_time[ip] = now
        seen_count[ip] = 1
    } else {
        # Reappeared within the retryperiod window; increment the counter.
        seen_count[ip]++
    }

    # Logic 2: Determine if the configured hit threshold has been reached
    if (seen_count[ip] >= max_hits) {
        callback = sprintf(run_external_format, cmd, ip)
        print callback
        fflush()
        system(callback)
        
        # Remove from records immediately upon triggering to prevent the IP from causing a barrage of duplicate alert storms during the same attack wave.
        delete seen_time[ip]
        delete seen_count[ip]
    }

    # Logic 3: [Optimization] Change the method of amortizing cleanup overhead from "by the number of valid IPs" to "by the passage of time".
    # Even if attacked 1,000 times in a single second, the cleanup action will still only execute once every (retryperiod / 2) seconds.
    if (now - last_cleanup > (retryperiod / 2)) {
        cleanup_seen(now)
        last_cleanup = now
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
    if (match($0, /ssh.+authentication failure;.*rhost=[0-9a-fA-F:.]+/)) {
        # Secondarily locate rhost=... directly within the entire line
        match($0, /rhost=[0-9a-fA-F:.]+/)
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
    else if (match($0, /ssh.+(Failed password|Invalid user|Connection).* from [0-9a-fA-F:.]+/)) {
        match($0, /from [0-9a-fA-F:.]+/)
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
    else if (match($0, /ssh.+(Disconnected|Disconnecting|Received disconnect|Unable to negotiate|Connection closed by|Connection reset by).* [0-9a-fA-F:.]+ .*preauth/)) {
        substr_match = substr($0, RSTART, RLENGTH)
        # Split the extracted log segment into words by spaces and iterate backwards
        # so the real attacker IP (near "port ... [preauth]") is always matched before a spoofed IP-like username.
        n_words = split(substr_match, words, " ")
        for (i = n_words; i >= 1; i--) {
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
    else if (match($0, /ssh.+Timeout before authentication for [0-9a-fA-F:.]+/)) {
        match($0, /for [0-9a-fA-F:.]+/)
        # RSTART+4 to skip "for "
        ip = substr($0, RSTART + 4, RLENGTH - 4)
        check_and_process(ip)
    }
}
