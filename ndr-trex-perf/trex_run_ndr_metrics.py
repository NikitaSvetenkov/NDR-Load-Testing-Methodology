#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

sys.path.insert(0, "/opt/trex/automation/trex_control_plane/interactive/trex/examples/astf")
import argparse
import os
import re
import time
import astf_path
import socket
import threading
import signal
import logging
import json
from copy import deepcopy
from itertools import cycle
from trex.astf.api import ASTFProfile, TRexError, TRexTimeoutError, ASTFClient
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError
from distutils import util
from flatten_json import flatten
import paramiko

SCRIPT_ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
SINGLE_ATTACK_PROFILE = os.path.join(SCRIPT_ROOT_PATH, 'trex_profiles', 'attack_single.py')
MAIN_PROFILE_ID = 'main_profile'
ATTACK_PROFILE_ID = 'attack_profile_{0}'

MAIN_STATS = {'m_traffic_duration': 'workload duration (sec)',
              'udps_sndbyte': 'UDP TX bytes',
              'udps_rcvbyte': 'UDP RX bytes',
              'udps_sndpkt': 'UDP TX packets',
              'udps_rcvpkt': 'UDP RX packets',
              'udps_keepdrops': 'UDP session drops',
              'udps_accepts': 'UDP connections accepted',
              'udps_connects': 'UDP connections established',
              'udps_closed': 'UDP conn. closed (including drops)',
              'tcps_connects': 'TCP connections established',
              'tcps_closed': 'TCP conn. closed (including drops)',
              'tcps_sndtotal': 'TCP TX packets',
              'tcps_sndbyte': 'TCP TX bytes',
              'tcps_rcvtotal': 'TCP RX packets',
              'tcps_rcvbyte': 'TCP RX bytes',
              'tcps_drops': 'TCP session drops',
              'm_tx_ratio': 'TX bw vs retransmits bw',
              'm_avg_size': 'Avg packet size bytes',
              }
DEBUG_STATS = ['err_c_nf_throttled',
               'err_c_tuple_err',
               'err_cwf',
               'err_dct',
               'err_defer_no_template',
               'err_flow_overflow',
               'err_fragments_ipv4_drop',
               'err_l3_cs',
               'err_l4_cs',
               'err_len_err',
               'err_no_memory',
               'err_no_syn',
               'err_no_tcp_udp',
               'err_no_template',
               'err_redirect_rx',
               'err_rx_throttled',
               'err_s_nf_throttled',
               'flows_other',
               'ignored_ips',
               'ignored_macs',
               'rss_redirect_drops',
               'rss_redirect_queue_full',
               'rss_redirect_rx',
               'rss_redirect_tx',
               'tcps_badsyn',
               'tcps_conndrops',
               'tcps_delack',
               'tcps_keepdrops',
               'tcps_keeptimeo',
               'tcps_nombuf',
               'tcps_pawsdrop',
               'tcps_persistdrop',
               'tcps_persisttimeo',
               'tcps_rcvafterclose',
               'tcps_rcvbadoff',
               'tcps_rcvbadsum',
               'tcps_rcvpackafterwin',
               'tcps_rcvdupack',
               'tcps_rcvduppack',
               'tcps_rcvoffloads',
               'tcps_rcvoopack',
               'tcps_rcvoopackdrop',
               'tcps_rcvshort',
               'tcps_rcvwinupd',
               'tcps_rexmttimeo',
               'tcps_rexmttimeo_syn',
               'tcps_sndrexmitpack',
               'tcps_sndurg',
               'tcps_sndwinup',
               'tcps_testdrops',
               'tcps_timeoutdrop',
               'udps_nombuf',
               'udps_pkt_toobig',
               'tcps_connattempt',
               'tcps_testdrops',
               ]

RETRY = 5
KPI_GLOBAL = {
    'tx_bps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'rx_bps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'tx_pps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'rx_pps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'active_flows': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'tx_cps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'queue_full': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'cpu_util': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    }
}
GRAFANA_DASHBOARDS_NGFW = [
    'pt-ngfw',
    'linux',
]
GRAFANA_DASHBOARDS_TREX = [
    'cisco-trex',
]
DEFAULT_TIMEOUT_SEC = 100

# ---------- DPDK stats parsing functions (добавлено) ----------
def human_readable_size(size_str: str) -> str:
    return size_str.strip().replace("(", "").replace(")", "").strip()

def human_to_bytes(human: str) -> int:
    human = human.replace("bytes", "").replace(" ", "").strip()
    match = re.match(r'([\d.]+)([GMK]?i?B?)', human)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2).upper()
    multipliers = {
        '': 1, 'B': 1,
        'K': 1024, 'KI': 1024, 'KB': 1024,
        'M': 1024 ** 2, 'MI': 1024 ** 2, 'MB': 1024 ** 2,
        'G': 1024 ** 3, 'GI': 1024 ** 3, 'GB': 1024 ** 3,
    }
    return int(value * multipliers.get(unit, 1))

def pkts_to_human(pkts_str: str) -> str:
    return pkts_str.strip().replace("(", "").replace(")", "").replace("pkts", "").strip()

def pkts_to_int(pkts_str: str) -> int:
    pkts_str = pkts_str.strip().replace("pkts", "").replace(" ", "").replace("(", "").replace(")", "")
    match = re.match(r'([\d.]+)([KM]?)?', pkts_str)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2).upper() if match.group(2) else ''
    multipliers = {'': 1, 'K': 1000, 'M': 1000 ** 2}
    return int(value * multipliers.get(unit, 1))

def parse_dpdk_stats(filepath=None, content=None):
    """
    Парсит файл dpdk_ifconfig или переданное содержимое.
    Возвращает словарь с числовыми метриками всех физических и логических интерфейсов.
    """
    data = {'physical': {}, 'logical': {}}
    if filepath:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            return data
    elif content:
        lines = content.splitlines()
    else:
        return data

    current_dev = None
    current_port = None

    for line in lines:
        line = line.rstrip()
        m_dev = re.match(r'^(dev_\d+)\s+Link encap:', line.strip())
        if m_dev:
            current_dev = m_dev.group(1)
            data['physical'][current_dev] = {
                'rx_bytes_human': '—', 'rx_bytes': 0,
                'rx_packets': 0,
                'errors': 0, 'dropped': 0, 'mis': 0
            }
            continue

        if current_dev:
            m_rx_bytes = re.search(r'RX bytes:(\d+)\s+\(([^)]+)\)', line)
            if m_rx_bytes:
                data['physical'][current_dev]['rx_bytes'] = int(m_rx_bytes.group(1))
                data['physical'][current_dev]['rx_bytes_human'] = human_readable_size(m_rx_bytes.group(2))

            m_rx_stats = re.search(r'RX packets:(\d+)\s+errors:(\d+).*?\(mis:\s*(\d+)\).*?dropped:(\d+)', line)
            if m_rx_stats:
                data['physical'][current_dev]['rx_packets'] = int(m_rx_stats.group(1))
                data['physical'][current_dev]['errors'] = int(m_rx_stats.group(2))
                data['physical'][current_dev]['mis'] = int(m_rx_stats.group(3))
                data['physical'][current_dev]['dropped'] = int(m_rx_stats.group(4))

        m_port = re.search(r'^Output port\s+([a-z0-9_]+):', line.strip())
        if m_port:
            current_port = m_port.group(1)
            data['logical'][current_port] = {
                'tx_bytes_human': '—', 'tx_bytes': 0,
                'tx_pkts_human': '—', 'tx_pkts': 0,
                'dropped_bytes_human': '—', 'dropped_bytes': 0,
                'dropped_pkts_human': '—', 'dropped_pkts': 0
            }
            continue

        if current_port:
            m_tx = re.search(r'TX\s*:\s*.*?\(([^)]+ bytes)\).*?\(([^)]+ pkts?)\)', line)
            if m_tx:
                data['logical'][current_port]['tx_bytes_human'] = human_readable_size(m_tx.group(1))
                data['logical'][current_port]['tx_bytes'] = human_to_bytes(m_tx.group(1))
                data['logical'][current_port]['tx_pkts_human'] = pkts_to_human(m_tx.group(2))
                data['logical'][current_port]['tx_pkts'] = pkts_to_int(m_tx.group(2))

            m_drop = re.search(r'Dropped\s*:\s*.*?\(([^)]+ bytes)\).*?\(([^)]+ pkts?)\)', line)
            if m_drop:
                data['logical'][current_port]['dropped_bytes_human'] = human_readable_size(m_drop.group(1))
                data['logical'][current_port]['dropped_bytes'] = human_to_bytes(m_drop.group(1))
                data['logical'][current_port]['dropped_pkts_human'] = pkts_to_human(m_drop.group(2))
                data['logical'][current_port]['dropped_pkts'] = pkts_to_int(m_drop.group(2))

    return data


# ------------------------------------------------------------

class Keyvalue(argparse.Action):
    # Constructor calling
    def __call__(self, parser, namespace,
                 values, option_string=None):
        setattr(namespace, self.dest, dict())
        for value in values:
            # split it into key and value
            key, value = value.split('=')
            # assign into dictionary
            getattr(namespace, self.dest)[key] = value


def grafana_url(host, from_time, to_time, trex, test_id, ngfw_host):
    time_offset = 10_000  # 10 Seconds time offset
    grafana_url_sample = "{0}/d/{1}/{1}?var-hostname={2}&var-test_id={3}&from={4}&to={5}"
    dashboards = {}
    if ngfw_host:
        for dash in GRAFANA_DASHBOARDS_NGFW:
            dashboards[dash] = grafana_url_sample.format(host, dash, ngfw_host, test_id,
                                                          from_time - time_offset, to_time + time_offset)
    for dash in GRAFANA_DASHBOARDS_TREX:
        dashboards[dash] = grafana_url_sample.format(host, dash, trex, test_id,
                                                      from_time - time_offset, to_time + time_offset)
    return dashboards


def clear_influx_db(client, db_name):
    try:
        client.drop_database(db_name)
        client.create_database(db_name)
        logging.info(f"Recreated database: {db_name}")
    except Exception as err:
        logging.error(f"Error recreating DB: {err}")


def influx_stat(host, test, profile, profile_path, stats, mult, latency_pps):
    points = []
    global_stats = stats['global']
    traffic_stats = stats['traffic']
    json_body = {
        "measurement": "trex_tests",
        "tags": {
            "host": host,
            "test_id": test,
            "profile": profile
        },
        "fields": {
        }
    }
    # Metrics description https://github.com/cisco-system-traffic-generator/trex-core/blob/master/scripts/automation/trex_control_plane/doc/api/json_fields.rst?plain=1#L135
    if latency_pps:
        json_body_lat = deepcopy(json_body)
        json_body_lat['measurement'] = 'trex_tests_latency'
        latency_stats = stats['latency']
        for port in latency_stats:
            json_body_lat['tags']['port'] = port
            port_stat_hist = latency_stats[port]['hist']['histogram']
            del latency_stats[port]['hist']['histogram']
            port_stat = flatten(latency_stats[port])
            for metric in port_stat:
                json_body_lat['fields']['latency_' + metric] = round(float(port_stat[metric]), 2)
            points.append(deepcopy(json_body_lat))
            json_body_lat['fields'] = {}
            total_pckts = sum(element['val'] for element in port_stat_hist)
            for hist_metric in port_stat_hist:
                json_body_lat['tags']['latency_usec'] = hist_metric['key']
                json_body_lat['fields']['pckt_prcnt'] = round(float((hist_metric['val'] / total_pckts) * 100), 2)
                points.append(deepcopy(json_body_lat))
                json_body_lat['fields'] = {}
    for k, v in global_stats.items():
        json_body['fields']['global_' + k] = round(float(v), 2)
    json_body['fields']['profile_name'] = profile
    json_body['fields']['profile_path'] = profile_path
    json_body['fields']['profile_mult_float'] = mult
    for direction in traffic_stats:
        for metric in MAIN_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]), 2)
        for metric in DEBUG_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]), 2)
    tcp_total_tx = traffic_stats['client'].get('tcps_sndtotal', 0) + traffic_stats['server'].get('tcps_sndtotal', 0)
    udp_total_tx = traffic_stats['client'].get('udps_sndpkt', 0) + traffic_stats['server'].get('udps_sndpkt', 0)
    tcp_total_tx_b = traffic_stats['client'].get('tcps_sndbyte', 0) + traffic_stats['server'].get('tcps_sndbyte', 0)
    tcp_total_rx_b = traffic_stats['client'].get('tcps_rcvbyte', 0) + traffic_stats['server'].get('tcps_rcvbyte', 0)
    udp_total_tx_b = traffic_stats['client'].get('udps_sndbyte', 0) + traffic_stats['server'].get('udps_sndbyte', 0)
    udp_total_rx_b = traffic_stats['client'].get('udps_rcvbyte', 0) + traffic_stats['server'].get('udps_rcvbyte', 0)
    tcp_drops_b = tcp_total_tx_b - tcp_total_rx_b
    udp_drops_b = udp_total_tx_b - udp_total_rx_b
    json_body['fields']['profile_total_tcp_tx'] = round(float(tcp_total_tx), 2)
    json_body['fields']['profile_total_udp_tx'] = round(float(udp_total_tx), 2)
    json_body['fields']['profile_total_tcp_tx_bytes'] = round(float(tcp_total_tx_b), 2)
    json_body['fields']['profile_total_udp_tx_bytes'] = round(float(udp_total_tx_b), 2)
    json_body['fields']['profile_total_tcp_drops_bytes'] = round(float(tcp_drops_b), 2)
    json_body['fields']['profile_total_udp_drops_bytes'] = round(float(udp_drops_b), 2)
    points.append(json_body)
    try:
        flux_client.write_points(points)
    except Exception as err:
        logging.info(err)
    return 0


def influxdb_send_annotation(host, test, description):
    json_body = {
        "measurement": "events",
        "fields": {
            "text": description,
            "test_id": test
        },
        "tags": {
            "host": host,
            "test_id": test,
        }
    }
    points = [json_body, ]
    try:
        flux_client.write_points(points)
    except Exception as err:
        logging.info(err)


def cyclic_stat(host, test, profile, profile_path, interval, mult, latency_pps, tunables, duration, cc_duration):
    skipped_kpi_start_period = float(tunables.get('ramp_up', 0)) if tunables else 0
    skipped_kpi_end_period = duration
    t_start = time.time()
    if cc_duration:
        skipped_kpi_start_period = duration
        skipped_kpi_end_period = duration + cc_duration
    while c.is_traffic_active():
        t_delta = time.time() - t_start
        stats = c.get_stats(skip_zero=False, pid_input=profile, is_sum=False)
        if skipped_kpi_start_period < t_delta < skipped_kpi_end_period:
            for kpi in KPI_GLOBAL:
                KPI_GLOBAL[kpi]['sum'] += stats['global'][kpi]
                KPI_GLOBAL[kpi]['count'] += 1
                KPI_GLOBAL[kpi]['avg'] = KPI_GLOBAL[kpi]['sum'] / KPI_GLOBAL[kpi]['count']
        influx_stat(host, test, profile, profile_path, stats, mult, latency_pps)
        time.sleep(interval)
    return 0


def get_all_files(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in sorted(filenames):
            yield os.path.abspath(os.path.join(dirpath, f))


def get_test_main_stat(stats, drops, error_timeout):
    main_stats = {
        'main_profile':
            {
                'client': {},
                'server': {},
                'global': {},
                'asserts': []
            }
    }
    for direction in stats['traffic']:
        if stats['traffic'][direction]['m_traffic_duration']:
            for metric in MAIN_STATS:
                if stats['traffic'][direction][metric]:
                    main_stats['main_profile'][direction][MAIN_STATS[metric]] = round(
                        stats['traffic'][direction][metric])
            avg_tx_pps = round(
                (stats['traffic'][direction]['udps_sndpkt'] + stats['traffic'][direction]['tcps_sndpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            avg_rx_pps = round(
                (stats['traffic'][direction]['udps_rcvpkt'] + stats['traffic'][direction]['tcps_rcvpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            main_stats['main_profile'][direction]['avg_tx_pps'] = avg_tx_pps
            main_stats['main_profile'][direction]['avg_rx_pps'] = avg_rx_pps
            # if not stats['traffic'][direction]['udps_keepdrops'] and not stats['traffic'][direction]['tcps_drops']:
            # main_stats['main_profile'][direction]['tcp_udp_drops'] = 0
            # else:
            # main_stats['main_profile'][direction]['tcp_udp_drops'] = stats['traffic'][direction]['udps_keepdrops'] \
            # + stats['traffic'][direction]['tcps_drops']
        else:
            main_stats['main_profile'][direction][MAIN_STATS['m_traffic_duration']] = 0
    client_stats = stats['traffic']['client']
    server_stats = stats['traffic']['server']
    tcp_total_tx_b = client_stats.get('tcps_sndbyte', 0) + server_stats.get('tcps_sndbyte', 0)
    udp_total_tx_b = client_stats.get('udps_sndbyte', 0) + server_stats.get('udps_sndbyte', 0)
    tcps_drops = client_stats.get('tcps_connattempt', 0) - server_stats.get('tcps_closed', 0) + server_stats.get('tcps_drops', 0) \
                 + server_stats.get('tcps_conndrops', 0) + server_stats.get('tcps_keepdrops', 0) + server_stats.get('tcps_timeoutdrop', 0) \
                 + server_stats.get('tcps_testdrops', 0)
    udps_drops = client_stats.get('udps_connects', 0) - server_stats.get('udps_closed', 0) + server_stats.get('udps_keepdrops', 0)
    conn_drp = round(float(((tcps_drops + udps_drops) / stats['global']['open_flows']) * 100), 4) if \
        stats['global']['open_flows'] else 0
    main_stats['main_profile']['global']['conn_drp_pct'] = conn_drp
    main_stats['main_profile']['error_timeout'] = error_timeout
    for kpi in KPI_GLOBAL:
        main_stats['main_profile']['global'][kpi] = int(KPI_GLOBAL[kpi]['avg'])
    if tcp_total_tx_b + udp_total_tx_b == 0:
        main_stats['main_profile']['asserts'].append('No any TCP or UDP sent App bytes')
    if conn_drp > drops:
        main_stats['main_profile']['asserts'].append('Too much drops (in connections): %s%%.'
                                                     ' Total conn drops: %s'
                                                     % (conn_drp, udps_drops + tcps_drops))
    return main_stats


def get_attack_stat(stats):
    attack_stats = {
        'attack_profiles':
            {
                'total_sent': 0,
                'blocked_ips': 0,
                'blocked_not_only_ips': 0,
                'allowed': 0,
                'skipped': 0,
                'allowed_list': [],
                'skipped_list': [],
                'asserts': []
            },
        'total_not_established_connections': 0
    }
    total_attacks = stats['total_blocked_ips'] + stats['total_blocked_not_only_ips'] + stats['total_allowed']
    attack_stats['attack_profiles']['total_sent'] = total_attacks
    attack_stats['attack_profiles']['blocked_ips'] = stats['total_blocked_ips']
    attack_stats['attack_profiles']['blocked_not_only_ips'] = stats['total_blocked_not_only_ips']
    attack_stats['attack_profiles']['allowed'] = stats['total_allowed']
    attack_stats['attack_profiles']['skipped'] = stats['total_skipped']
    if stats['total_allowed']:
        for attack in stats['allowed_set']:
            attack_stats['attack_profiles']['allowed_list'].append(attack)
    if stats['total_skipped']:
        for attack in stats['skipped_set']:
            attack_stats['attack_profiles']['skipped_list'].append(attack)
    if attack_stats['attack_profiles']['allowed'] > 0:
        attack_stats['attack_profiles']['asserts'].append('Found allowed attacks: %s.'
                                                          % (attack_stats['attack_profiles']['allowed']))
    attack_stats['total_not_established_connections'] = stats['total_not_established_conn']
    return attack_stats


def signal_handler(sig, frame):
    logging.warning('Abortion by user. Stop trex traffic.')
    c.reset()
    c.clear_stats()
    exit(0)


def start_traffic_capture(trex_client):
    cap_meta = trex_client.start_capture(tx_ports=0, rx_ports=0)
    print(f'Start pcap capture: {cap_meta["id"]}')
    return cap_meta['id']


def stop_traffic_capture(cap_id, output):
    logging.info(f"Save captured packets to {output}")
    c.stop_capture(cap_id, output=output)


def astf_test(mult, duration, profile_path, attacks_path,
              drops, tunables, send_stats, test, influx_interval, latency_pps, cc_duration, attack_intv, pcap_cap,
              attacks_once):
    t_result = {'test_id': test}
    logging.info('Start test {}'.format(test))
    timeout_duration = DEFAULT_TIMEOUT_SEC
    if duration < 0:
        timeout_duration = 0
    if cc_duration > 0:
        timeout_duration = timeout_duration + duration + cc_duration
    error_timeout = False

    if profile_path:
        profile_name = os.path.basename(profile_path)
        try:
            if tunables:
                profile = ASTFProfile.load(profile_path, **tunables)
                c.load_profile(profile, pid_input=MAIN_PROFILE_ID)

                if 'ramp_up' in tunables and duration > 0:
                    duration = duration + float(tunables['ramp_up'])
            else:
                profile = ASTFProfile.load(profile_path)
                c.load_profile(profile, pid_input=MAIN_PROFILE_ID)
        except TRexError as e:
            logging.error(e)
            exit(1)
        try_num = 1
        while not c.get_profiles_state().get(MAIN_PROFILE_ID):
            if try_num > RETRY:
                logging.error("Profile {} wasn't loaded. Exit.".format(MAIN_PROFILE_ID))
                exit(1)
            logging.info('Wait on profile load (%s/%s)...' % (try_num, RETRY))
            try_num += 1
            time.sleep(0.2)
        if pcap_cap:
            cap_id = start_traffic_capture(c)
        try:
            c.start(t_duration=timeout_duration, pid_input=MAIN_PROFILE_ID, mult=mult, duration=duration,
                    latency_pps=latency_pps)
        except TRexError as e:
            t_result['error'] = str(e)
            print(json.dumps(t_result, indent=2))
            logging.info(f'Stop the test: {e}')
            exit(1)
        logging.info("Start main profile %s with %s multiplier for %s seconds" % (profile_path, mult, duration))
        if send_stats:
            thread_stat = threading.Thread(target=cyclic_stat,
                                           args=(trex_host, test, MAIN_PROFILE_ID, profile_path, influx_interval, mult,
                                                 latency_pps, tunables, duration, cc_duration))
            thread_stat.start()

    if attacks_path:
        system_info = c.get_server_system_info()
        dp_cores_num = system_info['dp_core_count']
        attacks_all = get_all_files(attacks_path)
        attacks_pool = cycle(attacks_all)
        attack_index = 1
        if attacks_once:
            stop_time = 0
        elif duration > 0:
            stop_time = time.time() + duration
        else:
            stop_time = float("inf")
        attack_stats = {'total_blocked_ips': 0,
                        'total_blocked_not_only_ips': 0,
                        'total_allowed': 0,
                        'total_skipped': 0,
                        'total_not_established_conn': 0,
                        'allowed_set': set(),
                        'skipped_set': set()
                        }
        remaining_attacks = len(list(get_all_files(attacks_path))) if attacks_once else 0
        while time.time() < stop_time or remaining_attacks > 0:
            absolute_pcap_path = next(attacks_pool)
            _, relative_pcap_path = os.path.split(absolute_pcap_path)
            if relative_pcap_path in attack_stats['skipped_set']:
                remaining_attacks -= 1
                continue
            logging.info("Send attack {0} using pcap {1}".format(attack_index, relative_pcap_path))
            c.load_profile(SINGLE_ATTACK_PROFILE, pid_input=ATTACK_PROFILE_ID.format(attack_index),
                           tunables={"pcap": absolute_pcap_path, "dp_cores": dp_cores_num})
            try:
                c.start(t_duration=timeout_duration, pid_input=ATTACK_PROFILE_ID.format(attack_index), mult=1.0,
                        duration=1)
            except TRexError as e:
                dport = re.findall(r'port (\d+)', str(e))[0]
                logging.info('Skip attack {0}: the same DST '
                             'port as for the main profile ({1}).'.format(attack_index, dport))
                attack_stats['total_skipped'] += 1
                attack_stats['skipped_set'].add(relative_pcap_path)
                c.stop(block=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_remove=True)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                time.sleep(attack_intv)
                remaining_attacks -= 1
                continue
            else:
                c.wait_on_traffic(profile_id=ATTACK_PROFILE_ID.format(attack_index))
                stats = c.get_stats(skip_zero=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_sum=False)
                not_established_conn = stats['traffic']['client']['tcps_connattempt'] \
                                       + stats['traffic']['client']['udps_connects'] \
                                       - stats['traffic']['server']['tcps_closed'] \
                                       - stats['traffic']['server']['udps_closed']
                conn_drops = stats['traffic']['server']['tcps_drops'] + stats['traffic']['server']['udps_keepdrops']
                conn_closed = stats['traffic']['server']['tcps_closed'] + stats['traffic']['server']['udps_closed']
                conn_allowed = conn_closed - conn_drops
                if not conn_allowed and not_established_conn:
                    logging.info(f"Attack {attack_index} was blocked not only by IPS. "
                                 f"Blocked connections by IPS: {conn_drops}. "
                                 f"Not established connections: {not_established_conn}")
                    attack_stats['total_blocked_not_only_ips'] += 1
                elif not conn_allowed and not not_established_conn:
                    logging.info(f"Attack {attack_index} was blocked by IPS. Blocked connections by IPS: {conn_drops}.")
                    attack_stats['total_blocked_ips'] += 1
                else:
                    logging.info(f"Attack {attack_index} was allowed. Allowed connections by IPS: {conn_allowed}. "
                                 f"Blocked connections by IPS: {conn_drops}. "
                                 f"Not established connections: {not_established_conn}")
                    attack_stats['total_allowed'] += 1
                    attack_stats['allowed_set'].add(relative_pcap_path)
                attack_stats['total_not_established_conn'] += not_established_conn
                if send_stats:
                    stats['global']['attack_allowed'] = bool(conn_allowed)
                    influx_stat(trex_host, test, ATTACK_PROFILE_ID.format(attack_index), relative_pcap_path, stats,
                                mult=1.0, latency_pps=0)
                c.clear_profile(pid_input=ATTACK_PROFILE_ID.format(attack_index), block=False)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                attack_index += 1
                remaining_attacks -= 1
                time.sleep(attack_intv)
    if profile_path:
        if attacks_once:
            c.stop(pid_input=MAIN_PROFILE_ID)
            logging.info(f'Waiting timeout {DEFAULT_TIMEOUT_SEC} seconds for closing connections.')
            time.sleep(DEFAULT_TIMEOUT_SEC)
        else:
            try:
                if timeout_duration:
                    c.wait_on_traffic(timeout=duration + timeout_duration, profile_id=MAIN_PROFILE_ID)
                else:
                    c.wait_on_traffic(profile_id=MAIN_PROFILE_ID)
            except TRexTimeoutError as e:
                logging.info(e)
                c.stop(pid_input=MAIN_PROFILE_ID)
                error_timeout = True
        if send_stats:
            thread_stat.join()
        logging.info("Stop main profile.")
        if pcap_cap:
            output_f = tunables['pattern'].replace('.yaml', '.pcap') if tunables.get('pattern', None) else \
                os.path.join(SCRIPT_ROOT_PATH, test + '_' + time.strftime("%Y-%m-%dT%H-%M-%S") + '.pcap')
            stop_traffic_capture(cap_id, output_f)
        main_stats = c.get_stats(skip_zero=False, pid_input=MAIN_PROFILE_ID, is_sum=False)
        if send_stats:
            influx_stat(trex_host, test, MAIN_PROFILE_ID, profile_path, main_stats, mult, latency_pps)
        test_main_stats = get_test_main_stat(main_stats, drops, error_timeout)
        t_result.update(test_main_stats)
    if attacks_path:
        test_attack_stats = get_attack_stat(attack_stats)
        t_result.update(test_attack_stats)
    t_result['result'] = 'Failed' if t_result.get('main_profile', {}).get('asserts', {}) or \
                                     t_result.get('attack_profiles', {}).get('asserts', {}) else 'Passed'
    c.disconnect()
    return t_result


def parse_args():
    parser = argparse.ArgumentParser(description='TRex ASTF mode',
                                      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-s',
                        dest='server',
                        help='remote TRex address',
                        default='127.0.0.1',
                        type=str)
    parser.add_argument('--sync_port',
                        dest='sync_port',
                        help='the RPC port',
                        default='4501',
                        type=int)
    parser.add_argument('--async_port',
                        dest='async_port',
                        help='the ASYNC port (subscriber port)',
                        default='4500',
                        type=int)
    parser.add_argument('--trex_instance',
                        dest='trex_instance',
                        help='Trex instance',
                        default=None)
    parser.add_argument('-m',
                        dest='mult',
                        help='multiplier of main traffic',
                        default=1.0,
                        type=float)
    parser.add_argument('-f',
                        dest='file',
                        help='profile path for sending main traffic',
                        type=str)
    parser.add_argument('-d',
                        default=10,
                        dest='duration',
                        help='duration of traffic, sec',
                        type=float)
    parser.add_argument('-a',
                        dest='attacks_path',
                        help='attack pcaps absolute path directory for sending attacks',
                        type=str)
    parser.add_argument('--drp',
                        default=0.1,
                        dest='drp',
                        help='Allowed main traffic drops (connections), %%',
                        type=float)
    parser.add_argument('-t',
                        dest='tunables',
                        help='tunables for main profile: key1=value1 key2=value2...',
                        nargs='*',
                        action=Keyvalue,
                        default={})
    parser.add_argument('--send_stats',
                        default=False,
                        dest='send_stats',
                        help='Send stats to InfluxDB',
                        type=util.strtobool)
    parser.add_argument('--clear_db',
                        dest='clear_db',
                        help='Clear InfluxDB measurements before test',
                        action="store_true",
                        default=False)
    parser.add_argument('--influx_addr',
                        dest='influx_addr',
                        help='InfluxDB address',
                        default='127.0.0.1',
                        type=str)
    parser.add_argument('--influx_port',
                        dest='influx_port',
                        help='InfluxDB port',
                        default=8086,
                        type=int)
    parser.add_argument('--influx_admin',
                        dest='influx_admin',
                        help='InfluxDB admin user',
                        default='admin',
                        type=str)
    parser.add_argument('--influx_passwd',
                        dest='influx_passwd',
                        help='InfluxDB admin password',
                        default='admin',
                        type=str)
    parser.add_argument('--influx_db',
                        dest='influx_db',
                        help='Influx DB name',
                        default='trex',
                        type=str)
    parser.add_argument('--influx_interval',
                        dest='influx_interval',
                        help='Influx send interval, sec',
                        default=10,
                        type=int)
    parser.add_argument('--grafana_url',
                        dest='grafana_url',
                        help='Grafana URL',
                        default='http://127.0.0.1:3000',
                        type=str)
    parser.add_argument('--latency_pps',
                        dest='latency_pps',
                        help='ICMP packets rate',
                        default=0,
                        type=int)
    parser.add_argument('--json',
                        dest='json_out',
                        help='Output in json format',
                        action="store_true",
                        default=False)
    parser.add_argument('--bw',
                        dest='get_bw',
                        help='Get resolved ports bandwidth',
                        action="store_true",
                        default=False)
    parser.add_argument('--ngfw-hostname',
                        dest='ngfw_host',
                        help='NGFW hostname for grafana dashboards',
                        default=None)
    parser.add_argument('--cc-dur',
                        dest='cc_duration',
                        help='Concurrent connections steady state duration, sec',
                        type=float,
                        default=0)
    parser.add_argument('--attack-interval',
                        dest='attack_interval',
                        help='Time interval between attacks sending, sec',
                        type=float,
                        default=1.0)
    parser.add_argument('--capture',
                        dest='pcap_cap',
                        help='Capture first 1000 pckts since starting main profile',
                        action="store_true",
                        default=False)
    parser.add_argument('--attacks-once',
                        dest='attacks_once',
                        help='Send all attacks only once',
                        action="store_true",
                        default=False)
    parser.add_argument('--arp-retries',
                        dest='arp_retries',
                        help='ARP retries with 1 second interval',
                        default=10,
                        type=int)
    parser.add_argument("-u", "--username", default="admin", help="Имя пользователя для SSH (по умолчанию: admin)")
    parser.add_argument("-p", "--password", default="admin", help="Пароль для SSH (по умолчанию: admin)")
    parser.add_argument("-k", "--key", default=None,
                        help="Путь к файлу приватного SSH ключа (если указано, используется аутентификация по ключу вместо пароля)")
    parser.add_argument("--ip", default="127.0.0.1", help="IP адрес хоста (по умолчанию: 10.99.101.245)")

    # Дополнительный аргумент для DPDK файла (добавлено)
    parser.add_argument('--dpdk-file',
                        dest='dpdk_file',
                        help='Path to dpdk_ifconfig file for NDR monitoring',
                        default=None,
                        type=str)

    # Новые аргументы для мониторинга дисков
    parser.add_argument('--disk-monitor',
                        dest='disk_monitor',
                        help='Enable disk monitoring on remote host',
                        action='store_true',
                        default=False)
    parser.add_argument('--disk-interval',
                        dest='disk_interval',
                        help='Disk stats collection interval (seconds)',
                        default=5.0,
                        type=float)
    parser.add_argument('--disk-devices',
                        dest='disk_devices',
                        help='List of disk devices to monitor (e.g., sda nvme0n1). If not specified, monitor all.',
                        nargs='*',
                        default=None)

    return parser.parse_args()


signal.signal(signal.SIGINT, signal_handler)
args = parse_args()

log_level = 'WARN' if args.json_out else 'INFO'
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                    encoding='utf-8', level=log_level,
                    handlers=[logging.StreamHandler()])

if not args.file and not args.attacks_path:
    logging.error('Error: at least main profile or attacks path should be exist.')
    exit(1)

if args.send_stats:
    try:
        flux_client = InfluxDBClient(args.influx_addr, args.influx_port, args.influx_admin, args.influx_passwd,
                                     args.influx_db)
        flux_client.ping()

        if args.clear_db:
            clear_influx_db(flux_client, args.influx_db)
    except Exception as err:
        logging.error("InfluxDB Error: {0}.".format(err))
        exit(1)

if not args.trex_instance:
    args.trex_instance = 'trex1'
args.trex_ngfw = args.trex_instance + '-' + args.ngfw_host if args.ngfw_host else args.trex_instance

try:
    c = ASTFClient(server=args.server, sync_port=args.sync_port, async_port=args.async_port)
    c.connect()
    c.acquire(force=True)
    logging.info("Ports acquired successfully")
    c.reset()
    c.clear_stats()
    used_ports = c.get_acquired_ports()
    logging.info(f"Acquired ports: {used_ports}")

    if c.get_resolvable_ports():
        c.set_service_mode(ports=used_ports, enabled=True)
        for i in range(args.arp_retries):
            try:
                logging.info('Trying to resolve DUT ports...')
                c.arp(ports=used_ports)
                break
            except TRexError as e:
                logging.warning(f"ARP attempt {i + 1} failed: {e}")
                if i < args.arp_retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(f"ARP failed after {args.arp_retries} retries: {e}")
        c.set_service_mode(ports=used_ports, enabled=False)
except TRexError as e:
    logging.error(e)
    if 'used_ports' in locals():
        c.set_service_mode(ports=used_ports, enabled=False)
    c.disconnect()
    exit(1)
except Exception as e:
    logging.error(f"Unexpected error: {e}")
    exit(1)

if args.get_bw:
    ports_speed = []
    for port_id in used_ports:
        port_speed = c.get_port_attr(port_id)['speed']
        ports_speed.append(port_speed)
    result_port_speed = min(ports_speed)
    print(int(result_port_speed))
    exit(0)

trex_host = socket.gethostname()
start_time = int(time.time()) * 1000
if args.attacks_once:
    logging.warning(f'With key --attacks-once parameter -d will be ignored.')
    args.duration = -1

if args.send_stats:
    influxdb_send_annotation(trex_host, test=args.trex_ngfw, description="Start")

INFLUX_HOST = args.influx_addr
INFLUX_PORT = args.influx_port
stop_event = threading.Event()


def get_influx_client(influx_user, influx_passwd, influx_db):
    return InfluxDBClient(
        host=INFLUX_HOST,
        port=INFLUX_PORT,
        username=influx_user,
        password=influx_passwd,
        database=influx_db
    )


def get_cpu_usages_remote(ssh_client):
    """Возвращает (общая загрузка CPU, словарь загрузки по ядрам) через SSH, используя exec_command."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/stat | grep '^cpu'")
        output1 = stdout.read().decode().strip()
        lines1 = output1.splitlines()
    except Exception as e:
        logging.error(f"SSH exec error (first cpu): {e}")
        return 0.0, {}

    total_times1 = None
    per_core_times1 = {}
    for line in lines1:
        if not line.strip():
            continue
        parts = line.split()
        cpu_name = parts[0]
        try:
            times = [int(p) for p in parts[1:]]
        except ValueError:
            continue
        if cpu_name == 'cpu':
            total_times1 = times
        elif cpu_name.startswith('cpu'):
            cpu_id = cpu_name[3:]
            per_core_times1[cpu_id] = times

    time.sleep(1)

    try:
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/stat | grep '^cpu'")
        output2 = stdout.read().decode().strip()
        lines2 = output2.splitlines()
    except Exception as e:
        logging.error(f"SSH exec error (second cpu): {e}")
        return 0.0, {}

    total_times2 = None
    per_core_times2 = {}
    for line in lines2:
        if not line.strip():
            continue
        parts = line.split()
        cpu_name = parts[0]
        try:
            times = [int(p) for p in parts[1:]]
        except ValueError:
            continue
        if cpu_name == 'cpu':
            total_times2 = times
        elif cpu_name.startswith('cpu'):
            cpu_id = cpu_name[3:]
            per_core_times2[cpu_id] = times

    overall_usage = 0.0
    if total_times1 and total_times2 and len(total_times1) >= 5 and len(total_times2) >= 5:
        idle1 = total_times1[3] + total_times1[4]
        idle2 = total_times2[3] + total_times2[4]
        total1 = sum(total_times1)
        total2 = sum(total_times2)
        total_diff = total2 - total1
        idle_diff = idle2 - idle1
        if total_diff != 0:
            overall_usage = (total_diff - idle_diff) / total_diff * 100

    # По ядрам
    per_core = {}
    for cpu_id in per_core_times1:
        if cpu_id in per_core_times2:
            times1 = per_core_times1[cpu_id]
            times2 = per_core_times2[cpu_id]
            if len(times1) >= 5 and len(times2) >= 5:
                idle1 = times1[3] + times1[4]
                idle2 = times2[3] + times2[4]
                total1 = sum(times1)
                total2 = sum(times2)
                total_diff = total2 - total1
                idle_diff = idle2 - idle1
                if total_diff != 0:
                    usage = (total_diff - idle_diff) / total_diff * 100
                    per_core[cpu_id] = round(usage, 2)

    overall_usage = round(overall_usage, 2)
    return overall_usage, per_core


def monitor_cpu(host, user, password, key=None):
    """Поток сбора CPU статистики."""
    influx = get_influx_client(args.influx_admin, args.influx_passwd, args.influx_db)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key:
            ssh.connect(host, port=22, username=user, key_filename=key, timeout=10)
        else:
            ssh.connect(host, port=22, username=user, password=password, timeout=10)
        logging.info(f"SSH connected to {host} for CPU monitoring")
    except Exception as e:
        logging.error(f"SSH connection failed for CPU monitoring: {e}")
        return

    try:
        while not stop_event.is_set():
            overall_usage, per_core = get_cpu_usages_remote(ssh)
            json_body_overall = [{
                "measurement": "cpu_load",
                "fields": {"cpu_usage_percent": overall_usage},
                "tags": {"host": host, "core": "overall"},
                "time": int(time.time() * 1_000_000_000)
            }]
            try:
                influx.write_points(json_body_overall, time_precision='n')
            except InfluxDBClientError as e:
                logging.error(f"Influx write error (cpu overall): {e}")
            for core, usage in per_core.items():
                json_body_core = [{
                    "measurement": "cpu_load",
                    "fields": {"cpu_usage_percent": usage},
                    "tags": {"host": host, "core": core},
                    "time": int(time.time() * 1_000_000_000)
                }]
                try:
                    influx.write_points(json_body_core, time_precision='n')
                except InfluxDBClientError as e:
                    logging.error(f"Influx write error (cpu core {core}): {e}")
            time.sleep(2)
    except Exception as e:
        logging.error(f"Unexpected error in CPU monitor: {e}")
    finally:
        ssh.close()
        logging.info("CPU monitor thread finished")


def get_memory_usage(ssh_client):
    """Возвращает (mem_used_MB, mem_total_MB, swap_used_MB, swap_total_MB) через SSH."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command("cat /proc/meminfo")
        output = stdout.read().decode()
    except Exception as e:
        logging.error(f"SSH exec error (meminfo): {e}")
        return 0, 0, 0, 0

    meminfo = {}
    for line in output.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(":", 1)
        try:
            val = int(value.strip().split()[0])
            meminfo[key.strip()] = val
        except (ValueError, IndexError):
            continue

    mem_total = meminfo.get("MemTotal", 0)
    mem_free = meminfo.get("MemFree", 0)
    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)
    sreclaimable = meminfo.get("SReclaimable", 0)
    shmem = meminfo.get("Shmem", 0)

    cached_total = cached + sreclaimable - shmem
    mem_used = mem_total - mem_free - buffers - cached_total

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = swap_total - swap_free

    return mem_used / 1024, mem_total / 1024, swap_used / 1024, swap_total / 1024


def monitor_memory(host, user, password, key=None):
    """Поток сбора памяти."""
    influx = get_influx_client(args.influx_admin, args.influx_passwd, args.influx_db)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key:
            ssh.connect(host, port=22, username=user, key_filename=key, timeout=10)
        else:
            ssh.connect(host, port=22, username=user, password=password, timeout=10)
        logging.info(f"SSH connected to {host} for memory monitoring")
    except Exception as e:
        logging.error(f"SSH connection failed for memory monitoring: {e}")
        return

    try:
        while not stop_event.is_set():
            mem_used, mem_total, swap_used, swap_total = get_memory_usage(ssh)
            mem_percent = (mem_used / mem_total * 100) if mem_total > 0 else 0
            swap_percent = (swap_used / swap_total * 100) if swap_total > 0 else 0

            json_body = [{
                "measurement": "memory_usage",
                "fields": {
                    "mem_used_mb": round(mem_used, 2),
                    "mem_total_mb": round(mem_total, 2),
                    "mem_percent": round(mem_percent, 2),
                    "swap_used_mb": round(swap_used, 2),
                    "swap_total_mb": round(swap_total, 2),
                    "swap_percent": round(swap_percent, 2)
                },
                "tags": {"host": host},
                "time": int(time.time() * 1_000_000_000)
            }]
            try:
                influx.write_points(json_body, time_precision='n')
            except InfluxDBClientError as e:
                logging.error(f"Influx write error (memory): {e}")
            time.sleep(4)
    except Exception as e:
        logging.error(f"Unexpected error in memory monitor: {e}")
    finally:
        ssh.close()
        logging.info("Memory monitor thread finished")


def monitor_dpdk(host, dpdk_file, test_id, stop_event, user, password, key=None):
    """Поток сбора метрик DPDK интерфейсов (физических и логических) с удалённого хоста."""
    influx = get_influx_client(args.influx_admin, args.influx_passwd, args.influx_db)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key:
            ssh.connect(host, port=22, username=user, key_filename=key, timeout=10)
        else:
            ssh.connect(host, port=22, username=user, password=password, timeout=10)
        logging.info(f"SSH connected to {host} for DPDK monitoring")
    except Exception as e:
        logging.error(f"SSH connection failed for DPDK monitoring: {e}")
        return

    # Хранилища для первого и предыдущего снимков
    initial_stats = None
    prev_stats = None
    prev_time = None

    while not stop_event.is_set():
        try:
            now = time.time()
            # Чтение файла через SSH
            stdin, stdout, stderr = ssh.exec_command(f"cat {dpdk_file}")
            content = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode().strip()
            if err:
                if "No such file" in err:
                    logging.warning(f"DPDK file {dpdk_file} not found on remote host, waiting...")
                else:
                    logging.error(f"Error reading DPDK file: {err}")
                time.sleep(2)
                continue

            stats = parse_dpdk_stats(content=content)

            # Инициализация при первом запуске
            if initial_stats is None:
                initial_stats = stats
                prev_stats = stats
                prev_time = now
                # Пропускаем отправку в первом цикле, чтобы накопить данные
                time.sleep(2)
                continue

            delta_time = now - prev_time

            # Отправка физических портов
            for dev, dev_stats in stats.get('physical', {}).items():
                init_dev = initial_stats.get('physical', {}).get(dev, {})
                prev_dev = prev_stats.get('physical', {}).get(dev, {})

                fields_abs = {
                    'rx_bytes': dev_stats.get('rx_bytes', 0),
                    'rx_packets': dev_stats.get('rx_packets', 0),
                    'errors': dev_stats.get('errors', 0),
                    'mis': dev_stats.get('mis', 0),
                    'dropped': dev_stats.get('dropped', 0),
                }
                fields_delta = {
                    'rx_bytes_delta': dev_stats.get('rx_bytes', 0) - init_dev.get('rx_bytes', 0),
                    'rx_packets_delta': dev_stats.get('rx_packets', 0) - init_dev.get('rx_packets', 0),
                    'errors_delta': dev_stats.get('errors', 0) - init_dev.get('errors', 0),
                    'mis_delta': dev_stats.get('mis', 0) - init_dev.get('mis', 0),
                    'dropped_delta': dev_stats.get('dropped', 0) - init_dev.get('dropped', 0),
                }
                fields_rate = {}
                if delta_time > 0:
                    fields_rate = {
                        'rx_bytes_rate': (dev_stats.get('rx_bytes', 0) - prev_dev.get('rx_bytes', 0)) / delta_time,
                        'rx_packets_rate': (dev_stats.get('rx_packets', 0) - prev_dev.get('rx_packets', 0)) / delta_time,
                        'errors_rate': (dev_stats.get('errors', 0) - prev_dev.get('errors', 0)) / delta_time,
                        'mis_rate': (dev_stats.get('mis', 0) - prev_dev.get('mis', 0)) / delta_time,
                        'dropped_rate': (dev_stats.get('dropped', 0) - prev_dev.get('dropped', 0)) / delta_time,
                    }

                tags = {
                    'host': host,
                    'test_id': test_id,
                    'type': 'physical',
                    'device': dev
                }
                point = {
                    "measurement": "ndr",
                    "tags": tags,
                    "fields": {**fields_abs, **fields_delta, **fields_rate},
                    "time": int(now * 1_000_000_000)
                }
                try:
                    influx.write_points([point], time_precision='n')
                except Exception as e:
                    logging.error(f"Influx write error (dpdk physical {dev}): {e}")

            # Отправка логических портов
            for port, port_stats in stats.get('logical', {}).items():
                init_port = initial_stats.get('logical', {}).get(port, {})
                prev_port = prev_stats.get('logical', {}).get(port, {})

                fields_abs = {
                    'tx_bytes': port_stats.get('tx_bytes', 0),
                    'tx_pkts': port_stats.get('tx_pkts', 0),
                    'dropped_bytes': port_stats.get('dropped_bytes', 0),
                    'dropped_pkts': port_stats.get('dropped_pkts', 0),
                }
                fields_delta = {
                    'tx_bytes_delta': port_stats.get('tx_bytes', 0) - init_port.get('tx_bytes', 0),
                    'tx_pkts_delta': port_stats.get('tx_pkts', 0) - init_port.get('tx_pkts', 0),
                    'dropped_bytes_delta': port_stats.get('dropped_bytes', 0) - init_port.get('dropped_bytes', 0),
                    'dropped_pkts_delta': port_stats.get('dropped_pkts', 0) - init_port.get('dropped_pkts', 0),
                }
                fields_rate = {}
                if delta_time > 0:
                    fields_rate = {
                        'tx_bytes_rate': (port_stats.get('tx_bytes', 0) - prev_port.get('tx_bytes', 0)) / delta_time,
                        'tx_pkts_rate': (port_stats.get('tx_pkts', 0) - prev_port.get('tx_pkts', 0)) / delta_time,
                        'dropped_bytes_rate': (port_stats.get('dropped_bytes', 0) - prev_port.get('dropped_bytes', 0)) / delta_time,
                        'dropped_pkts_rate': (port_stats.get('dropped_pkts', 0) - prev_port.get('dropped_pkts', 0)) / delta_time,
                    }

                tags = {
                    'host': host,
                    'test_id': test_id,
                    'type': 'logical',
                    'port': port
                }
                point = {
                    "measurement": "ndr",
                    "tags": tags,
                    "fields": {**fields_abs, **fields_delta, **fields_rate},
                    "time": int(now * 1_000_000_000)
                }
                try:
                    influx.write_points([point], time_precision='n')
                except Exception as e:
                    logging.error(f"Influx write error (dpdk logical {port}): {e}")

            # Обновляем предыдущие значения
            prev_stats = stats
            prev_time = now

        except Exception as e:
            logging.error(f"Error in DPDK monitor loop: {e}")

        time.sleep(2)

    ssh.close()
    logging.info("DPDK monitor thread finished")


# ---------- Новые функции для мониторинга дисков ----------
def get_remote_block_devices(ssh_client, filter_devices=None):
    """Возвращает список блочных устройств на удалённом хосте, исключая виртуальные."""
    exclude = ('loop', 'ram', 'dm-', 'md', 'sr', 'fd', 'nbd', 'zram')
    try:
        stdin, stdout, stderr = ssh_client.exec_command("ls /sys/block")
        output = stdout.read().decode().strip()
        if not output:
            return []
        devices = [d for d in output.splitlines() if d and not any(d.startswith(x) for x in exclude)]
    except Exception as e:
        logging.error(f"Error listing block devices: {e}")
        return []

    if filter_devices:
        # фильтр по заданным именам (без /dev/)
        filter_devices = [d.strip() for d in filter_devices]
        devices = [d for d in devices if d in filter_devices]
    return sorted(devices)


def read_remote_stat(ssh_client, dev):
    """Читает /sys/block/<dev>/stat через SSH, возвращает список int."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(f"cat /sys/block/{dev}/stat")
        line = stdout.read().decode().strip()
        if not line:
            return [0] * 20
        return [int(x) for x in line.split()]
    except Exception:
        return [0] * 20


def get_remote_device_info(ssh_client, dev):
    """Возвращает (size_gb, model) для устройства."""
    size_gb = 0.0
    model = "N/A"
    try:
        stdin, stdout, stderr = ssh_client.exec_command(f"cat /sys/block/{dev}/size")
        size_str = stdout.read().decode().strip()
        if size_str:
            size_gb = round(int(size_str) * 512 / (1024 ** 3), 1)
    except Exception:
        pass

    try:
        stdin, stdout, stderr = ssh_client.exec_command(f"cat /sys/block/{dev}/device/model")
        model = stdout.read().decode().strip()[:18]
        if not model:
            model = "N/A"
    except Exception:
        pass
    return size_gb, model


def monitor_disks(host, user, password, key, interval, test_id, filter_devices=None):
    """Поток сбора метрик дисков с удалённого хоста и отправки в InfluxDB (измерение diskmon)."""
    influx = get_influx_client(args.influx_admin, args.influx_passwd, args.influx_db)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key:
            ssh.connect(host, port=22, username=user, key_filename=key, timeout=10)
        else:
            ssh.connect(host, port=22, username=user, password=password, timeout=10)
        logging.info(f"SSH connected to {host} for disk monitoring")
    except Exception as e:
        logging.error(f"SSH connection failed for disk monitoring: {e}")
        return

    # Хранилище предыдущих значений для каждого устройства
    prev_stats = {}
    prev_time = None

    try:
        while not stop_event.is_set():
            now = time.time()
            # Получаем список устройств (может меняться, но редко)
            devices = get_remote_block_devices(ssh, filter_devices)
            if not devices:
                logging.warning("No block devices found on remote host")
                time.sleep(interval)
                continue

            # Если первый запуск, просто запоминаем время и статистику, ничего не отправляем
            if prev_time is None:
                for dev in devices:
                    prev_stats[dev] = read_remote_stat(ssh, dev)
                prev_time = now
                time.sleep(interval)
                continue

            delta_time = now - prev_time
            if delta_time <= 0:
                delta_time = interval  # fallback

            total_points = []

            for dev in devices:
                curr = read_remote_stat(ssh, dev)
                p = prev_stats.get(dev, [0] * 20)

                # Разности за интервал (поля stat: 0 reads, 2 read sectors, 3 read time, 4 writes, 6 write sectors, 7 write time, 9 io time, 10 weighted io time)
                d_reads = curr[0] - p[0]
                d_writes = curr[4] - p[4]
                d_sec_r = curr[2] - p[2]
                d_sec_w = curr[6] - p[6]
                d_time_r = curr[3] - p[3]
                d_time_w = curr[7] - p[7]
                d_io_time = curr[9] - p[9]
                d_weighted = curr[10] - p[10]

                total_ios = d_reads + d_writes
                if total_ios == 0:
                    total_ios = 1  # избегаем деления на ноль

                # per-second метрики
                rps = d_reads / delta_time
                wps = d_writes / delta_time
                rkbs = d_sec_r * 0.5 / delta_time  # секторы по 512 байт -> KB
                wkbs = d_sec_w * 0.5 / delta_time

                await_ms = (d_time_r + d_time_w) / total_ios
                r_await = d_time_r / d_reads if d_reads else 0.0
                w_await = d_time_w / d_writes if d_writes else 0.0

                util = min(100.0, d_io_time / (delta_time * 1000) * 100)  # io_time в миллисекундах
                avgqu_sz = d_weighted / (delta_time * 1000)  # weighted time in ms -> средняя длина очереди

                size_gb, model = get_remote_device_info(ssh, dev)

                # Формируем точку InfluxDB
                fields = {
                    'size_gb': float(size_gb),
                    'rps': float(round(rps, 2)),
                    'wps': float(round(wps, 2)),
                    'rkbs': float(round(rkbs, 2)),
                    'wkbs': float(round(wkbs, 2)),
                    'await_ms': float(round(await_ms, 2)),
                    'r_await_ms': float(round(r_await, 2)),
                    'w_await_ms': float(round(w_await, 2)),
                    'util_percent': float(round(util, 2)),
                    'avgqu_sz': float(round(avgqu_sz, 2)),
                    # Можно добавить и абсолютные счётчики, если нужно
                    'read_ios': int(curr[0]),
                    'write_ios': int(curr[4]),
                    'read_sectors': int(curr[2]),
                    'write_sectors': int(curr[6]),
                }

                tags = {
                    'host': host,
                    'test_id': test_id,
                    'device': dev,
                    'model': model
                }

                point = {
                    "measurement": "diskmon",
                    "tags": tags,
                    "fields": fields,
                    "time": int(now * 1_000_000_000)  # наносекунды
                }
                total_points.append(point)

                # Обновляем предыдущее значение для этого устройства
                prev_stats[dev] = curr

            # Отправляем пачкой
            if total_points:
                try:
                    influx.write_points(total_points, time_precision='n')
                except Exception as e:
                    logging.error(f"Influx write error (diskmon): {e}")

            prev_time = now
            time.sleep(interval)

    except Exception as e:
        logging.error(f"Unexpected error in disk monitor: {e}")
    finally:
        ssh.close()
        logging.info("Disk monitor thread finished")


# ------------------------------------------------------------

if args.send_stats:
    threads = [
        threading.Thread(target=monitor_cpu, args=(args.ip, args.username, args.password, args.key)),
        threading.Thread(target=monitor_memory, args=(args.ip, args.username, args.password, args.key)),
    ]
    if args.dpdk_file:
        threads.append(threading.Thread(target=monitor_dpdk,
                                        args=(args.ip, args.dpdk_file, args.trex_ngfw, stop_event,
                                              args.username, args.password, args.key)))
    if args.disk_monitor:
        threads.append(threading.Thread(target=monitor_disks,
                                        args=(args.ip, args.username, args.password, args.key,
                                              args.disk_interval, args.trex_ngfw, args.disk_devices)))
    for t in threads:
        t.daemon = True
        t.start()
else:
    threads = []

test_result = {}
try:
    test_result = astf_test(mult=args.mult, duration=args.duration, profile_path=args.file,
                            attacks_path=args.attacks_path, drops=args.drp, tunables=args.tunables,
                            send_stats=args.send_stats, test=args.trex_ngfw, influx_interval=args.influx_interval,
                            latency_pps=args.latency_pps, cc_duration=args.cc_duration, attack_intv=args.attack_interval,
                            pcap_cap=args.pcap_cap, attacks_once=args.attacks_once)
finally:
    if args.send_stats:
        stop_event.set()
        influxdb_send_annotation(trex_host, test=args.trex_ngfw, description="Stop")
        end_time = int(time.time()) * 1000
        test_result['grafana_urls'] = grafana_url(args.grafana_url, start_time, end_time, trex_host, args.trex_ngfw,
                                                  args.ngfw_host)
        for t in threads:
            t.join(timeout=5)

print(json.dumps(test_result, indent=2))