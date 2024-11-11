#!/usr/bin/env python
#############################################################################
# Copyright (c) 2024 Balazs Scheidler <balazs.scheidler@axoflow.com>
# Copyright (c) 2024 Axoflow
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# As an additional exemption you are allowed to compile & link against the
# OpenSSL libraries as published by the OpenSSL project. See the file
# COPYING for details.
#
#############################################################################
from pathlib import Path

from src.common.blocking import wait_until_true
from src.common.file import File
from src.common.file import copy_shared_file
from src.common.random_id import get_unique_id


def _write_auto_config(config, syslog_ng, port_allocator, transport, testcase_parameters):
    server_key_path = copy_shared_file(testcase_parameters, "server.key")
    server_cert_path = copy_shared_file(testcase_parameters, "server.crt")

    output_file = "output.log"

    syslog_source = config.create_syslog_source(
        ip="localhost",
        port=port_allocator(),
        keep_hostname="yes",
        transport=transport,
        tls={
            "key-file": server_key_path,
            "cert-file": server_cert_path,
            "peer-verify": '"optional-untrusted"',
        },
    )
    file_destination = config.create_file_destination(file_name=output_file)
    config.create_logpath(statements=[syslog_source, file_destination])

    syslog_ng.start(config)
    return (syslog_source, file_destination)

def _test_auto_detect(syslog_source, file_destination, loggen, input_messages, number_of_messages, expected_messages, use_ssl=False, proxied=False, proxied_tls_passthrough=False):

    loggen_input_file_path = Path("loggen_input_{}.txt".format(get_unique_id()))
    loggen_input_file = File(loggen_input_file_path)
    loggen_input_file.write_content_and_close(input_messages)
    loggen.start(
        syslog_source.options["ip"], syslog_source.options["port"],
        number=number_of_messages+(1 if proxied else 0),
        dont_parse=True,
        read_file=str(loggen_input_file_path),
        syslog_proto=True,
        inet=None if use_ssl else True,
        use_ssl=use_ssl,
        proxied=1 if proxied else None,
        proxied_tls_passthrough=proxied_tls_passthrough,
        proxy_src_ip="1.1.1.1", proxy_dst_ip="2.2.2.2", proxy_src_port="3333", proxy_dst_port="4444",
    )

    wait_until_true(lambda: loggen.get_sent_message_count() == number_of_messages)

    assert file_destination.read_log() == expected_messages

    loggen.stop()


def test_auto_framing(config, syslog_ng, syslog_ng_ctl, port_allocator, loggen, testcase_parameters):
    NUMBER_OF_MESSAGES = 10
    INPUT_MESSAGES = "52 <2>Oct 11 22:14:15 myhostname sshd[1234]: message 0\n" * NUMBER_OF_MESSAGES
    EXPECTED_MESSAGES = "Oct 11 22:14:15 myhostname sshd[1234]: message 0\n"
    (syslog_source, file_destination) = _write_auto_config(config, syslog_ng, port_allocator, '"auto"', testcase_parameters)

    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES)

def test_auto_framing_tls(config, syslog_ng, syslog_ng_ctl, port_allocator, loggen, testcase_parameters):
    NUMBER_OF_MESSAGES = 10
    INPUT_MESSAGES = "52 <2>Oct 11 22:14:15 myhostname sshd[1234]: message 0\n" * NUMBER_OF_MESSAGES
    EXPECTED_MESSAGES = "Oct 11 22:14:15 myhostname sshd[1234]: message 0\n"
    (syslog_source, file_destination) = _write_auto_config(config, syslog_ng, port_allocator, '"auto"', testcase_parameters)

    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES,
                      use_ssl=True)

def test_auto_framing_tls_proxied(config, syslog_ng, syslog_ng_ctl, port_allocator, loggen, testcase_parameters):
    NUMBER_OF_MESSAGES = 10
    INPUT_MESSAGES = "52 <2>Oct 11 22:14:15 myhostname sshd[1234]: message 0\n" * NUMBER_OF_MESSAGES
    EXPECTED_MESSAGES = "Oct 11 22:14:15 myhostname sshd[1234]: message 0\n"
    (syslog_source, file_destination) = _write_auto_config(config, syslog_ng, port_allocator, '"auto"', testcase_parameters)

    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES,
                      use_ssl=True, proxied=True)

def test_auto_framing_tls_proxied_passthrough(config, syslog_ng, syslog_ng_ctl, port_allocator, loggen, testcase_parameters):
    NUMBER_OF_MESSAGES = 10
    INPUT_MESSAGES = "52 <2>Oct 11 22:14:15 myhostname sshd[1234]: message 0\n" * NUMBER_OF_MESSAGES
    EXPECTED_MESSAGES = "Oct 11 22:14:15 myhostname sshd[1234]: message 0\n"
    (syslog_source, file_destination) = _write_auto_config(config, syslog_ng, port_allocator, '"auto"', testcase_parameters)

    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES,
                      use_ssl=True, proxied=True, proxied_tls_passthrough=True)


def test_auto_no_framing(config, syslog_ng, syslog_ng_ctl, port_allocator, loggen, testcase_parameters):
    NUMBER_OF_MESSAGES = 10
    INPUT_MESSAGES = "<2>Oct 11 22:14:15 myhostname sshd[1234]: message 0\n" * NUMBER_OF_MESSAGES
    EXPECTED_MESSAGES = "Oct 11 22:14:15 myhostname sshd[1234]: message 0\n"

    (syslog_source, file_destination) = _write_auto_config(config, syslog_ng, port_allocator, '"auto"', testcase_parameters)
    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES)

    _test_auto_detect(syslog_source, file_destination, loggen,
                      INPUT_MESSAGES, NUMBER_OF_MESSAGES, EXPECTED_MESSAGES,
                      use_ssl=True)
