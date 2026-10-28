"""Log parser tests: realistic Linux auth, router and firewall formats; unknown lines are ignored."""

import unittest
from datetime import datetime, timedelta, timezone

from helpers import ROOT  # noqa: F401  (sets sys.path)
from bgagent.parsers import parse_auth_line, parse_header, parse_syslog

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


def auth(line):
    return parse_auth_line(f"Oct 28 11:59:00 homeserver {line}", "homeserver", NOW, timezone.utc)


class AuthLogTests(unittest.TestCase):
    def test_ssh_failed_and_invalid_user(self):
        e = auth("sshd[1]: Failed password for invalid user oracle from 203.0.113.50 port 40000 ssh2")
        self.assertEqual((e["type"], e["actor"], e["source_ip"]), ("auth_failure", "oracle", "203.0.113.50"))
        self.assertTrue(e["details"]["invalid_user"])
        self.assertEqual(e["timestamp"], "2026-10-28T11:59:00+00:00")
        self.assertEqual(e["details"]["time_source"], "log")

    def test_ssh_accepted_publickey_ipv6(self):
        e = auth("sshd[1]: Accepted publickey for alex from 2001:db8::5 port 50000 ssh2: ED25519 SHA256:x")
        self.assertEqual((e["type"], e["actor"], e["source_ip"], e["details"]["method"]), ("auth_success", "alex", "2001:db8::5", "publickey"))

    def test_duplicate_pam_and_invalid_user_lines_are_not_double_counted(self):
        self.assertIsNone(auth("sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50  user=root"))
        self.assertIsNone(auth("sshd[1]: Invalid user oracle from 203.0.113.50 port 40000"))

    def test_sudo_variants(self):
        cmd = auth("sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m support2")
        self.assertEqual((cmd["type"], cmd["actor"], cmd["target"]), ("privilege_use", "deploy", "root"))
        bad = auth("sudo:     alex : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/bin/ls")
        self.assertEqual((bad["type"], bad["details"]["attempts"]), ("auth_failure", 3))
        denied = auth("sudo:    guest : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/sh")
        self.assertEqual(denied["details"]["reason"], "not_in_sudoers")

    def test_account_lifecycle(self):
        self.assertEqual(auth("useradd[1]: new user: name=support2, UID=1002, GID=1002, home=/home/support2, shell=/bin/sh")["target"], "support2")
        self.assertEqual(auth("userdel[1]: delete user 'olduser'")["type"], "account_deleted")
        group = auth("usermod[1]: add 'support2' to group 'sudo'")
        self.assertEqual((group["type"], group["target"], group["details"]["group"]), ("group_membership_change", "support2", "sudo"))
        gp = auth("gpasswd[1]: user bob added by root to group wheel")
        self.assertEqual((gp["actor"], gp["target"], gp["details"]["group"]), ("root", "bob", "wheel"))
        self.assertEqual(auth("passwd[1]: pam_unix(passwd:chauthtok): password changed for alex")["type"], "password_reset")

    def test_su(self):
        self.assertEqual(auth("su[1]: FAILED SU (to root) alex on pts/0")["type"], "auth_failure")
        self.assertEqual(auth("su[1]: (to root) alex on pts/0")["type"], "privilege_use")

    def test_unrelated_lines_ignored(self):
        for line in ("systemd[1]: Started Session 4.", "CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                     "sshd[1]: Received disconnect from 203.0.113.50 port 1:11: disconnected by user", "kernel: eth0 link up"):
            self.assertIsNone(auth(line), line)

    def test_iso_timestamps_and_year_rollover(self):
        e = parse_auth_line("2026-10-28T11:58:00.123456+00:00 homeserver sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
                            "homeserver", NOW)
        self.assertEqual(e["timestamp"], "2026-10-28T11:58:00+00:00")
        january = datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc)
        stamp, *_ = parse_header("Dec 31 23:59:00 h sshd[1]: x", january, timezone.utc)
        self.assertEqual(stamp.year, 2026)

    def test_future_log_time_falls_back_to_receive_time(self):
        e = parse_auth_line("2026-10-29T11:58:00+00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2", "h", NOW)
        self.assertEqual(e["details"]["time_source"], "received")
        self.assertEqual(e["timestamp"], NOW.isoformat(timespec="seconds"))


class SyslogTests(unittest.TestCase):
    def test_netfilter_drop_with_ports(self):
        e = parse_syslog(b"<4>Oct 28 11:59:00 OpenWrt kernel: [1.2] DROP wan in: IN=eth1 OUT= SRC=198.51.100.200 DST=203.0.113.10 PROTO=TCP SPT=6 DPT=3389",
                         "192.168.1.1", "Home router", NOW)
        self.assertEqual((e["type"], e["source_ip"], e["dest_ip"], e["dest_port"], e["host"]),
                         ("network_block", "198.51.100.200", "203.0.113.10", 3389, "Home router"))
        self.assertEqual(e["details"]["reported_hostname"], "OpenWrt")

    def test_ufw_block(self):
        e = parse_syslog("kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.77 DST=192.168.1.10 PROTO=TCP SPT=1 DPT=23", "10.0.0.1", "fw", NOW)
        self.assertEqual((e["type"], e["dest_port"]), ("network_block", 23))

    def test_pfsense_filterlog_block_and_pass(self):
        block = parse_syslog("<134>1 2026-10-28T11:59:00Z pfsense filterlog 6123 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,52,61234,0,DF,6,tcp,60,198.51.100.201,203.0.113.10,51234,3389,0,S",
                             "192.168.1.1", "pfSense", NOW)
        self.assertEqual((block["type"], block["source_ip"], block["dest_port"]), ("network_block", "198.51.100.201", 3389))
        self.assertIsNone(parse_syslog("<134>1 2026-10-28T11:59:00Z pfsense filterlog 1 - - 5,,,1,igb0,match,pass,out,4,0x0,,64,1,0,DF,17,udp,76,192.168.1.10,9.9.9.9,40000,53,56",
                                       "192.168.1.1", "pfSense", NOW))

    def test_dropbear_and_mikrotik(self):
        d = parse_syslog("<38>Oct 28 11:59:00 OpenWrt dropbear[1500]: Bad password attempt for 'root' from 192.168.1.66:50100", "192.168.1.1", "r", NOW)
        self.assertEqual((d["type"], d["actor"], d["source_ip"]), ("auth_failure", "root", "192.168.1.66"))
        m = parse_syslog("<29>Oct 28 11:59:00 MikroTik system,error,critical login failure for user admin from 192.168.88.250 via winbox", "192.168.88.1", "mt", NOW)
        self.assertEqual((m["type"], m["actor"], m["details"]["service"]), ("auth_failure", "admin", "winbox"))
        ok = parse_syslog("<29>Oct 28 11:59:00 MikroTik system,info,account user admin logged in from 192.168.88.10 via ssh", "192.168.88.1", "mt", NOW)
        self.assertEqual(ok["type"], "auth_success")
        change = parse_syslog("<29>Oct 28 11:59:00 MikroTik system,info firewall filter rule changed by admin", "192.168.88.1", "mt", NOW)
        self.assertEqual((change["type"], change["actor"]), ("config_change", "admin"))

    def test_dhcp_leases(self):
        d = parse_syslog("<30>Oct 28 11:59:00 OpenWrt dnsmasq-dhcp[1200]: DHCPACK(br-lan) 192.168.1.45 3c:22:fb:12:34:56 Kids-Tablet", "192.168.1.1", "r", NOW)
        self.assertEqual((d["type"], d["details"]["mac"], d["details"]["hostname"]), ("dhcp_lease", "3c:22:fb:12:34:56", "Kids-Tablet"))
        i = parse_syslog("dhcpd[9]: DHCPACK on 10.0.0.9 to aa:bb:cc:dd:ee:01 (printer) via eth0", "10.0.0.1", "r", NOW)
        self.assertEqual(i["details"]["hostname"], "printer")

    def test_generic_router_login_and_config(self):
        e = parse_syslog("httpd: Web management login failed from 192.168.1.99 user=admin", "192.168.1.1", "r", NOW)
        self.assertEqual((e["type"], e["source_ip"], e["actor"], e["details"]["match"]), ("auth_failure", "192.168.1.99", "admin", "generic"))
        self.assertEqual(parse_syslog("httpd: Configuration saved by admin", "192.168.1.1", "r", NOW)["type"], "config_change")

    def test_ignored_and_hostile_input(self):
        self.assertIsNone(parse_syslog(b"<30>Oct 28 11:59:00 OpenWrt netifd: Interface 'wan' is now up", "1.1.1.1", "r", NOW))
        self.assertIsNone(parse_syslog(b"", "1.1.1.1", "r", NOW))
        self.assertIsNone(parse_syslog(b"\xff\xfe\x00garbage", "1.1.1.1", "r", NOW))
        e = parse_syslog(("kernel: DROP IN=eth0 SRC=203.0.113.1 DST=203.0.113.2 " + "x" * 9000).encode(), "1.1.1.1", "r", NOW)
        self.assertLessEqual(len(e["message"]), 1000)
        bad_ip = parse_syslog("kernel: DROP IN=eth0 SRC=999.1.1.1 DST=203.0.113.2", "1.1.1.1", "r", NOW)
        self.assertEqual(bad_ip["source_ip"], "")

    def test_received_time_when_header_lacks_one(self):
        e = parse_syslog("dropbear[1]: Bad password attempt for 'root' from 192.168.1.66:1", "1.1.1.1", "r", NOW - timedelta(seconds=5))
        self.assertEqual(e["details"]["time_source"], "received")


if __name__ == "__main__":
    unittest.main()
