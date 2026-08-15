from trex.astf.api import *
import argparse



class Prof1():
    def init(self):
        pass

    def create_profile(self):

        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.1", "16.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        profile = ASTFProfile(default_ip_gen=ip_gen, cap_list=[
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_https_0.pcap", cps=108.0), 
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_http_get_0.pcap", cps=12.0,port=8080),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_http_post_0.pcap", cps=4.0,port=8081),

            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/udp.pcap", cps=10.0),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_smtp_0.pcap", cps=6.0),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/snmp.pcap", cps=2.0),

            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_mail_pop_0.pcap", cps=2.0),

            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/rdp_tls_1_2.pcap", cps=10.0),

            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/ssh_v2.pcap", cps=40.0),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/delay_10_dns_0.pcap", cps=2.0),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/smb.pcap", cps=2.0),
            ASTFCapInfo(file="/opt/trex/ndr-trex-perf-main/trex_profiles/tp/emix/emix_profiles/corp_ru/ftp.pcap", cps=2.0),            
        ])

        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        return self.create_profile()


def register():
    return Prof1()
