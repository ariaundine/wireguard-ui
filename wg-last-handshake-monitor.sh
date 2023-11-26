#!/bin/sh

send_email()
{
    local to_email="$1"
    local email_pattern="$2"
    local email_option="openssl s_client -quiet -tls1 -connect ${SMTP_HOSTNAME}:${SMTP_PORT}"

    if [ ! -e "${email_pattern}" ]; then
        return 0
    fi

    if [ "${SMTP_ENCRUPTION}" = "STARTTLS" ]; then
        email_option="openssl s_client -quiet -tls1 -starttls smtp -connect ${SMTP_HOSTNAME}:${SMTP_PORT}"
    fi

    sendmail -H "${email_option}" -am${SMTP_AUTH_TYPE} -au${SMTP_USERNAME} -ap${SMTP_PASSWORD} ${to_email} -v < "${email_pattern}"
}

send_wireguard_status_to_email()
{
    local content="$1"
    local wg_client_pubkey="$(echo "${content}" | awk '{print $2}')"
    local wg_client_config="$(grep "${wg_client_pubkey}" db/clients/* -l)"
    local wg_client_send_email_address="$(jq -r .email "${wg_client_config}")"
    local wg_client_name="$(jq -r .name "${wg_client_config}")"
    local wg_handshake_timeout="$(test ! -z ${WGUI_HANDSHAKE_TIMEOUT} && echo ${WGUI_HANDSHAKE_TIMEOUT} || echo 300)"
    local email_pattern=/tmp/email.content

    if [ -z "${wg_client_send_email_address}" ]; then
        return 0
    fi

cat > "${email_pattern}" <<EOL
Subject: Ainfolink VPN connection lost over time
Pay attention to the device name "${wg_client_name}", the VPN peer disconnection is over ${wg_handshake_timeout} seconds, check the wireguard service over here ${WGUI_MANAGER_URL} as well

Last handshake time: $(date -u -d @$(echo "${content}" | awk '{print $6}') +"%d-%m-%Y %T %z")

VPN status: "$(echo "${content}" | awk '{print "VPN IP: " $5 ", TX: " $7 " bytes, RX: " $8 " bytes"}')"
EOL

    send_email \
        "${wg_client_send_email_address}" \
        "${email_pattern}"
}

check_condition_for_resend_email_by_days()
{
    local wg_vpn_peer_ip="$1"
    # Calculate it to identify how long the handshake established server wait
    local wg_handshake_wait_over="$2"
    local wg_timeout_resend_by_days="$(test ! -z ${WGUI_TIMEOUT_RESEND_BY_DAYS} && echo ${WGUI_TIMEOUT_RESEND_BY_DAYS} || echo 30)"
    local wg_timeout_resend_period="$(( ${wg_timeout_resend_by_days} * 86400 ))"
    local wg_disconnection_record=/tmp/wg_disconnection_record
    local wg_client_record="$(grep "${wg_vpn_peer_ip}" "${wg_disconnection_record}")"
    local wg_current_disconnection_count="$(grep "${wg_vpn_peer_ip}" "${wg_disconnection_record}" | cut -d ':' -f 1)"
    local wg_disconnection_count=

    [ ! -e "${wg_disconnection_record}" ] && touch "${wg_disconnection_record}"

    if [ -z "${wg_client_record}" ]; then
        # Add new client failed information
        echo "0:${wg_vpn_peer_ip}" >> "${wg_disconnection_record}"
    else
        wg_disconnection_count="$(( ${wg_handshake_wait_over} / ${wg_timeout_resend_period} ))"
        if [ "${wg_current_disconnection_count}" -lt "${wg_disconnection_count}" ]; then
            # Update the failed resend check
            sed -i "s@${wg_current_disconnection_count}:${wg_vpn_peer_ip}@${wg_disconnection_count}:${wg_vpn_peer_ip}@g" "${wg_disconnection_record}"
        else
            # No need to notice the message resend signal because the timeout calculate is still under the timeout period
            return 0
        fi
    fi

    return 1
}

check_wireguard_connection_timeout()
{
    local current_time="$(date +'%s')"
    local wg_vpn_peer_ip="$1"
    # Detect the live handshake time of the VPN peer
    local wg_lasthandshake_time="$2"
    local wg_handshake_timeout="$(test ! -z ${WGUI_HANDSHAKE_TIMEOUT} && echo ${WGUI_HANDSHAKE_TIMEOUT} || echo 300)"
    # Calculate it to identify how long the handshake established server wait
    local wg_handshake_wait_over="$(( ${current_time} - ${wg_lasthandshake_time} ))"

    if [ "${current_time}" = "0" ] || [ "${wg_lasthandshake_time}" = "0" ]; then
        return 0
    fi

    if [ "${wg_handshake_wait_over}" -gt "${wg_handshake_timeout}" ]; then
        check_condition_for_resend_email_by_days "${wg_vpn_peer_ip}" "${wg_handshake_wait_over}"
        [ "$?" != "0" ] && return 1
    fi

    return 0
}

wireguard_last_handshake_detect()
{
    local wg_vpn_peer_ip=
    # Detect the live handshake time of the VPN peer
    local wg_lasthandshake_time=

    wg show all dump | while read content; do
        # Ensure the VPN peer is enabled
        wg_vpn_peer_ip="$(echo "${content}" | awk '{print $5}')"
        if [ "${wg_vpn_peer_ip}" = "off" ]; then
            continue
        fi
        # Detect the last handshake time since 1970 year
        wg_lasthandshake_time="$(echo "${content}" | awk '{print $6}')"

        check_wireguard_connection_timeout "${wg_vpn_peer_ip}" "${wg_lasthandshake_time}"

        [ "$?" != "0" ] && send_wireguard_status_to_email "${content}"
    done
}

wireguard_last_handshake_monitoring()
{
    local wg_disconnection_record=/tmp/wg_disconnection_record

    [ -e "${wg_disconnection_record}" ] && rm "${wg_disconnection_record}"

    while true; do
        wireguard_last_handshake_detect
        sleep 60
    done
}

wireguard_last_handshake_monitoring &
