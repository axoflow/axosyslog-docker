#!/usr/bin/env python
#############################################################################
# Copyright (c) 2024 Axoflow
# Copyright (c) 2024 Tamás Kosztyu <tamas.kosztyu@axoflow.com>
# Copyright (c) 2023 Balazs Scheidler <balazs.scheidler@axoflow.com>
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
import json
from datetime import datetime
from datetime import timezone

import pytest

from src.syslog_ng_config.renderer import render_statement


def create_config(config, filterx_expr_1, filterx_expr_2=None, msg="foobar", template="'$MSG\n'"):
    file_true = config.create_file_destination(file_name="dest-true.log", template=template)
    file_false = config.create_file_destination(file_name="dest-false.log", template=template)

    preamble = f"""
@version: {config.get_version()}

options {{ stats(level(1)); }};

source genmsg {{
    example-msg-generator(
        num(1)
        template("{msg}")
        values(
            "values.str" => string("string"),
            "values.bool" => boolean(true),
            "values.int" => int(5),
            "values.double" => double(32.5),
            "values.datetime" => datetime("1701350398.123000+01:00"),
            "values.list" => list("foo,bar,baz"),
            "values.null" => null(""),
            "values.bytes" => bytes("binary whatever"),
            "values.protobuf" => protobuf("this is not a valid protobuf!!"),
            "values.json" => json('{{"emb_key1": "emb_key1 value", "emb_key2": "emb_key2 value"}}'),
            "values.true_string" => string("boolean:true"),
            "values.false_string" => string("boolean:false"),
        )
    );
}};

destination dest_true {{
    {render_statement(file_true)};
}};

destination dest_false {{
    {render_statement(file_false)};
}};

log {{
    source(genmsg);
    if {{
        filterx {{ {filterx_expr_1} \n}};
        {"filterx { " + filterx_expr_2 + " };" if filterx_expr_2 is not None else ""}
        destination(dest_true);
    }} else {{
        destination(dest_false);
    }};
}};
"""
    config.set_raw_config(preamble)
    return (file_true, file_false)


def test_otel_logrecord_int32_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.dropped_attributes_count = ${values.int};
                                            $MSG = $olr.dropped_attributes_count; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "5\n"


def test_otel_logrecord_string_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.severity_text = "${values.str}";
                                            $MSG = $olr.severity_text; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "string\n"


def test_otel_logrecord_bytes_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.trace_id = ${values.bytes};
                                            $MSG = $olr.trace_id; """,
        template="""bytes('$MSG\n')""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "binary whatever\n"


def test_otel_logrecord_datetime_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.time_unix_nano = ${values.datetime};
                                            $MSG = $olr.time_unix_nano; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "1701353998.123000+00:00\n"


def test_otel_logrecord_body_string_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.str};
                                            $MSG = $olr.body; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "string\n"


def test_otel_logrecord_body_bool_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.bool};
                                            $MSG = $olr.body; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "true\n"


def test_otel_logrecord_body_int_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.int};
                                            $MSG = $olr.body; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "5\n"


def test_otel_logrecord_body_double_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.double};
                                            $MSG = $olr.body; """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "32.5\n"


def test_otel_logrecord_body_datetime_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.datetime};
                                            $MSG = $olr.body; """,
    )
    syslog_ng.start(config)

    # there is no implicit conversion back to datetime because anyvalue field
    # does not distinguish int_value and datetime.
    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "1701353998123000\n"


def test_otel_logrecord_body_bytes_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.bytes};
                                            $MSG = $olr.body; """,
        template="""bytes('$MSG\n')""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "binary whatever\n"


def test_otel_logrecord_body_protobuf_setter_getter(config, syslog_ng):
    # NOTE: protobuf is converted to bytes
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.protobuf};
                                            $MSG = $olr.body; """,
        template="""bytes('$MSG\n')""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "this is not a valid protobuf!!\n"


def test_otel_logrecord_body_json_setter_getter(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
                                            $olr = otel_logrecord();
                                            $olr.body = ${values.json};
                                            istype($olr.body, "otel_kvlist");
                                            $MSG = format_json($olr.body); """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"emb_key1":"emb_key1 value","emb_key2":"emb_key2 value"}\n'


def test_json_to_otel(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
                                            js = json({"foo": 42});
                                            js_arr = json_array([1, 2]);

                                            otel_kvl = otel_kvlist();

                                            otel_kvl.js = js;
                                            istype(otel_kvl.js, "otel_kvlist");
                                            otel_kvl.js += {"bar": 1337};

                                            otel_kvl.js_arr = js_arr;
                                            istype(otel_kvl.js_arr, "otel_array");
                                            otel_kvl.js_arr += [3, 4];

                                            $MSG = format_json(otel_kvl);
                """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"js":{"foo":42,"bar":1337},"js_arr":[1,2,3,4]}\n'


def test_otel_to_json(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
                                            otel_kvl = otel_kvlist({"foo": 42});
                                            otel_arr = otel_array([1, 2]);

                                            js = json();

                                            js.otel_kvl = otel_kvl;
                                            istype(js.otel_kvl, "json_object");
                                            js.otel_kvl += {"bar": 1337};

                                            js.otel_arr = otel_arr;
                                            istype(js.otel_arr, "json_array");
                                            js.otel_arr += [3, 4];

                                            $MSG = js;
                """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"otel_kvl":{"foo":42,"bar":1337},"otel_arr":[1,2,3,4]}\n'


def test_otel_resource_scope_log_to_json(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
                                            log = otel_logrecord();
                                            log += {
                                                "body": "fit",
                                                "time_unix_nano": 123456789,
                                                "attributes": {
                                                    "answer": 42,
                                                    "cool": true
                                                }
                                            };

                                            resource = otel_resource();
                                            resource.attributes["host.name"] = "szami.to";

                                            scope = otel_scope({
                                                "name": "oszcillo",
                                                "version": "ceta"
                                            });

                                            resource_js = json(resource);
                                            scope_js = json(scope);
                                            log_js = json(log);

                                            js = json({
                                                "in_dict_generator": {
                                                    "resource": resource,
                                                    "scope": scope,
                                                    "log": log,
                                                },
                                                "from_json_cast": {
                                                    "resource": resource_js,
                                                    "scope": scope_js,
                                                    "log": log_js,
                                                }
                                            });

                                            $MSG = js;
                """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert json.loads(file_true.read_log()) == {
        "in_dict_generator": {
            "resource": {
                "attributes": {
                    "host.name": "szami.to",
                },
            },
            "scope": {
                "name": "oszcillo",
                "version": "ceta",
            },
            "log": {
                "time_unix_nano": "123.456789",
                "body": "fit",
                "attributes": {
                    "answer": 42,
                    "cool": True,
                },
            },
        },
        "from_json_cast": {
            "resource": {
                "attributes": {
                    "host.name": "szami.to",
                },
            },
            "scope": {
                "name": "oszcillo",
                "version": "ceta",
            },
            "log": {
                "time_unix_nano": "123.456789",
                "body": "fit",
                "attributes": {
                    "answer": 42,
                    "cool": True,
                },
            },
        },
    }


def test_json_to_otel_resource_scope_log(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
                                            log_js = json();
                                            log_js += {
                                                "body": "fit",
                                                "time_unix_nano": 123456789,
                                                "attributes": {
                                                    "answer": 42,
                                                    "cool": true
                                                }
                                            };

                                            resource_js = json();
                                            resource_js.attributes = {};
                                            resource_js.attributes["host.name"] = "szami.to";

                                            scope_js = json({
                                                "name": "oszcillo",
                                                "version": "ceta"
                                            });

                                            resource = otel_resource(resource_js);
                                            scope = otel_scope(scope_js);
                                            log = otel_logrecord(log_js);

                                            js = json({
                                                "resource": resource,
                                                "scope": scope,
                                                "log": log,
                                            });

                                            $MSG = js;
                """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert json.loads(file_true.read_log()) == {
        "resource": {
            "attributes": {
                "host.name": "szami.to",
            },
        },
        "scope": {
            "name": "oszcillo",
            "version": "ceta",
        },
        "log": {
            "time_unix_nano": "123.456789",
            "body": "fit",
            "attributes": {
                "answer": 42,
                "cool": True,
            },
        },
    }


def test_simple_true_condition(config, syslog_ng):
    (file_true, file_false) = create_config(config, """ true; """)
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "foobar\n"


def test_empty_block(config, syslog_ng):
    (file_true, file_false) = create_config(config, """ """)
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "foobar\n"


def test_simple_false_condition(config, syslog_ng):
    (file_true, file_false) = create_config(config, """ false; """)
    syslog_ng.start(config)

    assert "processed" not in file_true.get_stats()
    assert file_false.get_stats()["processed"] == 1
    assert file_false.read_log() == "foobar\n"


def test_simple_assignment(config, syslog_ng):

    (file_true, file_false) = create_config(config, """ $MSG = "rewritten message!"; """)
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "rewritten message!\n"


def test_json_assignment_from_template(config, syslog_ng):

    (file_true, file_false) = create_config(config, """ $MSG = "$(format-json --subkeys values.)"; """)
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"true_string":"boolean:true","str":"string","null":null,"list":["foo","bar","baz"],"json":{"emb_key1": "emb_key1 value", "emb_key2": "emb_key2 value"},"int":5,"false_string":"boolean:false","double":32.5,"datetime":"1701350398.123000+01:00","bool":true}\n"""


def test_json_assignment_from_another_name_value_pair(config, syslog_ng):

    (file_true, file_false) = create_config(config, """ $MSG = ${values.json}; """)
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"emb_key1": "emb_key1 value", "emb_key2": "emb_key2 value"}\n"""


def test_json_getattr_returns_the_embedded_json(config, syslog_ng):

    (file_true, file_false) = create_config(
        config, """
$envelope = "$(format-json --subkeys values.)";
$MSG = $envelope.json.emb_key1;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """emb_key1 value\n"""


def test_json_setattr_sets_the_embedded_json(config, syslog_ng):

    (file_true, file_false) = create_config(
        config, """
$envelope = "$(format-json --subkeys values.)";
$envelope.json.new_key = "this is a new key!";
$MSG = $envelope.json;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"emb_key1":"emb_key1 value","emb_key2":"emb_key2 value","new_key":"this is a new key!"}\n"""


def test_json_assign_performs_a_deep_copy(config, syslog_ng):

    (file_true, file_false) = create_config(
        config, """
$envelope = "$(format-json --subkeys values.)";
$envelope.json.new_key = "this is a new key!";
$MSG = $envelope.json;
$envelope.json.another_key = "this is another new key which is not added to $MSG!";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"emb_key1":"emb_key1 value","emb_key2":"emb_key2 value","new_key":"this is a new key!"}\n"""


def test_json_simple_literal_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$MSG = json({
    "foo": "foovalue",
    "bar": "barvalue",
    "baz": "bazvalue"
});
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"foo":"foovalue","bar":"barvalue","baz":"bazvalue"}\n"""


def test_json_recursive_literal_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$MSG = json({
    "foo": "foovalue",
    "bar": "barvalue",
    "baz": "bazvalue",
    "recursive": {
        "foo": "foovalue",
        "bar": "barvalue",
        "baz": "bazvalue",
        "recursive": {
            "foo": "foovalue",
            "bar": "barvalue",
            "baz": "bazvalue",
        },
    },
});
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"foo":"foovalue","bar":"barvalue","baz":"bazvalue","recursive":{"foo":"foovalue","bar":"barvalue","baz":"bazvalue","recursive":{"foo":"foovalue","bar":"barvalue","baz":"bazvalue"}}}\n"""


def test_json_change_recursive_literal(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$MSG = json({
    "foo": "foovalue",
    "bar": "barvalue",
    "baz": "bazvalue",
    "recursive": {
        "foo": "foovalue",
        "bar": "barvalue",
        "baz": "bazvalue",
        "recursive": {
            "foo": "foovalue",
            "bar": "barvalue",
            "baz": "bazvalue",
        },
    },
});

$MSG.recursive.recursive.foo = "changedfoovalue";
$MSG.recursive.recursive.newattr = "newattrvalue";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """\
{"foo":"foovalue","bar":"barvalue","baz":"bazvalue",\
"recursive":{"foo":"foovalue","bar":"barvalue","baz":"bazvalue",\
"recursive":{"foo":"changedfoovalue","bar":"barvalue","baz":"bazvalue","newattr":"newattrvalue"}}}\n"""


def test_list_literal_becomes_syslogng_list_as_string(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$MSG = ["foo", "bar", "baz"];
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """foo,bar,baz\n"""


def test_list_literal_becomes_json_list_as_a_part_of_json(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$list = ["foo", "bar", "baz"];
$MSG = json({
    "key": "value",
    "list": $list,
});
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"key":"value","list":["foo","bar","baz"]}\n"""


def test_list_is_cloned_upon_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$list = ["foo", "bar", "baz"];
$MSG = $list;
$list[0] = "changed foo";
$MSG[2] = "changed baz";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    # foo remains unchanged while baz is changed
    assert file_true.read_log() == """foo,bar,"changed baz"\n"""


def test_list_subscript_without_index_appends_an_element(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$list = [];
$list[] = "foo";
$list[] = "bar";
$list[] = "baz";
$MSG = $list;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    # foo remains unchanged while baz is changed
    assert file_true.read_log() == """foo,bar,baz\n"""


def test_literal_generator_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
$MSG = {};  # implicit json
$MSG.foo = {"answer": 42, "leet": 1337};
$MSG["bar"] = {"answer+1": 43, "leet+1": 1338};
$MSG.list = ["will be replaced"];
$MSG.list[0] = [1, 2, 3];
$MSG.list[] = [4, 5, 6];
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"foo":{"answer":42,"leet":1337},"bar":{"answer+1":43,"leet+1":1338},"list":[[1,2,3],[4,5,6]]}\n"""


def test_literal_generator_casted_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$MSG = json();
$MSG.foo = json({"answer": 42, "leet": 1337});
$MSG["bar"] = json({"answer+1": 43, "leet+1": 1338});
$MSG.list = json_array(["will be replaced"]);
$MSG.list[0] = json_array([1, 2, 3]);
$MSG.list[] = json_array([4, 5, 6]);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == """{"foo":{"answer":42,"leet":1337},"bar":{"answer+1":43,"leet+1":1338},"list":[[1,2,3],[4,5,6]]}\n"""


def test_function_call(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
$list = [];
$list[] = "foo";
$list[] = "bar";
$list[] = "baz";
$MSG = example_echo($list);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    # foo remains unchanged while baz is changed
    assert file_true.read_log() == """foo,bar,baz\n"""


def test_ternary_operator_true(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = true?${values.true_string}:${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:true\n"


def test_ternary_operator_false(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = false?${values.true_string}:${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:false\n"


def test_ternary_operator_expression_true(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = (0 === 0)?${values.true_string}:${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:true\n"


def test_ternary_operator_expression_false(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = (0 === 1)?${values.true_string}:${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:false\n"


def test_ternary_operator_inline_ternary_expression_true(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = (0 === 0)?("foo" eq "foo"? ${values.true_string} : "inner:false"):${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:true\n"


def test_ternary_operator_inline_ternary_expression_false(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = (0 === 0)?("foo" eq "bar"? ${values.true_string} : "inner:false"):${values.false_string};
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "inner:false\n"


def test_ternary_return_condition_expression_value_without_true_branch(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = ${values.true_string}?:${values.false_string};
""",
    )

    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "boolean:true\n"


def test_if_condition_without_else_branch_match(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (true) {
        $out = "matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "matched\n"


def test_if_condition_without_else_branch_nomatch(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (false) {
        $out = "matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "default\n"


def test_if_condition_no_matching_condition(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (false) {
        $out = "matched";
    } elif (false) {
        $out = "elif-matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "default\n"


def test_if_condition_matching_main_condition(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (true) {
        $out = "matched";
    } elif (true) {
        $out = "elif-matched";
    } else {
        $out = "else-matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "matched\n"


def test_if_condition_matching_elif_condition(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (false) {
        $out = "matched";
    } elif (true) {
        $out = "elif-matched";
    } elif (true) {
        $out = "elif2-matched";
    } else {
        $out = "else-matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "elif-matched\n"


def test_if_condition_matching_else_condition(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if (false) {
        $out = "matched";
    } elif (false) {
        $out = "elif-matched";
    } else {
        $out = "else-matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "else-matched\n"


def test_if_condition_matching_expression(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if ("foo" eq "foo") {
        $out = "matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "matched\n"


def test_if_condition_non_matching_expression(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $out = "default";
    if ("foo" eq "bar") {
        $out = "matched";
    };
    $MSG = $out;
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "default\n"


def test_isset_existing_value_not_in_scope_yet(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    isset($MSG);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_isset_existing_value_already_in_scope(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG;
    isset($MSG);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_isset_inexisting_value_not_in_scope_yet(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    not isset($almafa);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_isset_inexisting_value_already_in_scope(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $almafa = "x";
    unset($almafa);
    not isset($almafa);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_isset(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = {};
    $MSG.inner_key = "foo";

    isset(${values.int});
    not isset($almafa);
    isset($MSG["inner_key"]);
    isset($MSG.inner_key);
    not isset($MSG["almafa"]);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_unset_value_not_in_scope_yet(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    unset($MSG);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "\n"


def test_unset_value_already_in_scope(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG;
    unset($MSG);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "\n"


def test_unset_existing_key(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = {};
    $MSG["foo"] = "bar";
    unset($MSG["foo"]);
    not isset($MSG["foo"]);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{}\n"


def test_unset_inexisting_key(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = {};
    unset($MSG["foo"]);
    not isset($MSG["foo"]);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{}\n"


def test_setting_an_unset_key_will_contain_the_right_value(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = {};
    $MSG["foo"] = "first";
    unset($MSG["foo"]);
    not isset($MSG["foo"]);
    $MSG["foo"] = "second";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"foo":"second"}\n'


def test_unset(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = {};
    $MSG["inner_key"] = "foo";
    $arr = [];
    $arr[] = "first";
    $arr[] = "second";

    unset(${values.int}, $almafa, $MSG["inner_key"], $MSG["almafa"], $arr[0]);

    not isset(${values.int});
    not isset($almafa);
    not isset($MSG["inner_key"]);
    not isset($MSG["almafa"]);
    isset($arr[0]);
    not isset($arr[1]);
    unset($MSG);
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "\n"


def test_strptime_error_result(config, syslog_ng):
    _ = create_config(
        config, """
        $MSG = strptime("2024-04-10T08:09:10Z"); # wrong arg set
""",
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_strftime_error_result(config, syslog_ng):
    _ = create_config(
        config, """
        $MSG = strftime("2024-04-10T08:09:10Z"); # wrong arg set
""",
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_strptime_success_result(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
        $MSG = strptime("2024-04-10T08:09:10Z", "%Y-%m-%dT%H:%M:%S%z");
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "1712736550.000000+00:00\n"


def test_strftime_success_result(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
        datetime = strptime("2000-01-01T00:00:00 +0200", "%Y-%m-%dT%H:%M:%S %z");
        $MSG = strftime("%Y-%m-%dT%H:%M:%S %z", datetime);
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "2000-01-01T00:00:00 +0200\n"


def test_strptime_guess_missing_year(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        $MSG = strptime("Sep 09 18:12:11Z", '%b %d %H:%M:%S%z');
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    timestamp_part = file_true.read_log().split('+')[0]
    # Assert that the timestamp is greater than January 1, 2024 (UTC). The exact year may vary due to aging.
    assert datetime.fromtimestamp(float(timestamp_part), tz=timezone.utc) > datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_strptime_failure_result(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
        $MSG = string(strptime("2024-04-10T08:09:10Z", "no", "valid", "parse", "fmt"));
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "null\n"


def test_len(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    $dict = {};
    $list = [];
    len($dict) == 0;
    len($list) == 0;

    $dict.foo = "bar";
    $list[] = "foo";
    len($dict) == 1;
    len($list) == 1;

    len(${values.str}) == 6;

    $MSG = "success";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "success\n"


def test_regexp_match(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    ${values.str} =~ /string/;
    ${values.str} =~ /.*/;
    not (${values.str} =~ /foobar/);
    "\"" =~ /"/;
    $MSG = "success";
""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "success\n"


def test_regexp_nomatch(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    $MSG = {};
    $MSG.match = ${values.str} !~ /string/;
    $MSG.match_any = ${values.str} !~ /.*/;
    $MSG.nomatch = ${values.str} !~ /wrong/;
    $MSG.match_inverse = not (${values.str} !~ /.*/);
    $MSG.nomatch_inverse = not (${values.str} !~ /foobar/);
""",
    )
    syslog_ng.start(config)

    exp = (
        r"""{"match":false,"""
        r""""match_any":false,"""
        r""""nomatch":true,"""
        r""""match_inverse":true,"""
        r""""nomatch_inverse":false}""" + "\n"
    )

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == exp


def test_regexp_match_error_in_pattern(config, syslog_ng):
    _ = create_config(
        config, r"""
    "foo" =~ /(/;
""",
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_regexp_search(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    $MSG = {};
    $MSG.unnamed = regexp_search("foobarbaz", /(foo)(bar)(baz)/);
    $MSG.unnamed_keep_zero = regexp_search("foobarbaz", /(foo)(bar)(baz)/, keep_zero=true);
    $MSG.unnamed_list_mode = regexp_search("foobarbaz", /(foo)(bar)(baz)/, list_mode=true);
    $MSG.unnamed_keep_zero_list_mode = regexp_search("foobarbaz", /(foo)(bar)(baz)/, keep_zero=true, list_mode=true);
    $MSG.named = regexp_search("foobarbaz", /(?<first>foo)(?<second>bar)(?<third>baz)/);
    $MSG.named_keep_zero = regexp_search("foobarbaz", /(?<first>foo)(?<second>bar)(?<third>baz)/, keep_zero=true);
    $MSG.named_list_mode = regexp_search("foobarbaz", /(?<first>foo)(?<second>bar)(?<third>baz)/, list_mode=true);
    $MSG.named_keep_zero_list_mode = regexp_search("foobarbaz", /(?<first>foo)(?<second>bar)(?<third>baz)/, keep_zero=true, list_mode=true);
    $MSG.mixed = regexp_search("foobarbaz", /(?<first>foo)(bar)(?<third>baz)/);
    $MSG.mixed_keep_zero = regexp_search("foobarbaz", /(?<first>foo)(bar)(?<third>baz)/, keep_zero=true);
    $MSG.mixed_list_mode = regexp_search("foobarbaz", /(?<first>foo)(bar)(?<third>baz)/, list_mode=true);
    $MSG.mixed_keep_zero_list_mode = regexp_search("foobarbaz", /(?<first>foo)(bar)(?<third>baz)/, keep_zero=true, list_mode=true);
    $MSG.force_list = json_array(regexp_search("foobarbaz", /(?<first>foo)(bar)(?<third>baz)/));
    $MSG.force_dict = json(regexp_search("foobarbaz", /(foo)(bar)(baz)/));
    $MSG.force_dict_list_mode = json(regexp_search("foobarbaz", /(foo)(bar)(baz)/, list_mode=true));

    $MSG.no_match_unnamed = regexp_search("foobarbaz", /(almafa)/);
    if (len($MSG.no_match_unnamed) == 0) {
        $MSG.no_match_unnamed_handling = true;
    };

    $MSG.no_match_unnamed_list_mode = regexp_search("foobarbaz", /(almafa)/, list_mode=true);
    if (len($MSG.no_match_unnamed_list_mode) == 0) {
        $MSG.no_match_unnamed_list_mode_handling = true;
    };

    $MSG.no_match_named = regexp_search("foobarbaz", /(?<first>almafa)/);
    if (len($MSG.no_match_named) == 0) {
        $MSG.no_match_named_handling = true;
    };

    $MSG.no_match_named_list_mode = regexp_search("foobarbaz", /(?<first>almafa)/, list_mode=true);
    if (len($MSG.no_match_named_list_mode) == 0) {
        $MSG.no_match_named_list_mode_handling = true;
    };

    $MSG.full_match=regexp_search("foobarbaz", /foobarbaz/);
    $MSG.full_match_list_mode=regexp_search("foobarbaz", /foobarbaz/, list_mode=true);

""",
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert json.loads(file_true.read_log()) == {
        "unnamed": {"1": "foo", "2": "bar", "3": "baz"},
        "unnamed_keep_zero": {"0": "foobarbaz", "1": "foo", "2": "bar", "3": "baz"},
        "unnamed_list_mode": ["foo", "bar", "baz"],
        "unnamed_keep_zero_list_mode": ["foobarbaz", "foo", "bar", "baz"],
        "named": {"first": "foo", "second": "bar", "third": "baz"},
        "named_keep_zero": {"0": "foobarbaz", "first": "foo", "second": "bar", "third": "baz"},
        "named_list_mode": ["foo", "bar", "baz"],
        "named_keep_zero_list_mode": ["foobarbaz", "foo", "bar", "baz"],
        "mixed": {"first": "foo", "2": "bar", "third": "baz"},
        "mixed_keep_zero": {"0": "foobarbaz", "first": "foo", "2": "bar", "third": "baz"},
        "mixed_list_mode": ["foo", "bar", "baz"],
        "mixed_keep_zero_list_mode": ["foobarbaz", "foo", "bar", "baz"],
        "force_list": ["foo", "bar", "baz"],
        "force_dict": {"1": "foo", "2": "bar", "3": "baz"},
        "force_dict_list_mode": {"1": "foo", "2": "bar", "3": "baz"},
        "no_match_unnamed": {},
        "no_match_unnamed_handling": True,
        "no_match_unnamed_list_mode": [],
        "no_match_unnamed_list_mode_handling": True,
        "no_match_named": {},
        "no_match_named_handling": True,
        "no_match_named_list_mode": [],
        "no_match_named_list_mode_handling": True,
        "full_match": {"0": "foobarbaz"},  # does not suppress grp 0 when it's the only result
        "full_match_list_mode": ["foobarbaz"],  # does not suppress grp 0 when it's the only result
    }


def test_regexp_search_error_in_pattern(config, syslog_ng):
    _ = create_config(
        config, r"""
    $MSG = regexp_search("foo", /(/);
""",
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_parse_kv_default_option_set_is_skippable(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = parse_kv("foo=bar, thisisstray bar=baz");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"foo":"bar","bar":"baz"}\n'


def test_parse_kv_value_separator(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = parse_kv("foo@bar, bar@baz", value_separator="@");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{\"foo\":\"bar\",\"bar\":\"baz\"}\n"


def test_parse_kv_value_separator_use_first_character(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = parse_kv("foo@bar, bar@baz", value_separator="@!$");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{\"foo\":\"bar\",\"bar\":\"baz\"}\n"


def test_parse_kv_pair_separator(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = parse_kv("foo=bar#bar=baz", pair_separator="#");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{\"foo\":\"bar\",\"bar\":\"baz\"}\n"


def test_parse_kv_stray_words_value_name(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    $MSG = parse_kv("foo=bar, thisisstray bar=baz", stray_words_key="stray_words");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{\"foo\":\"bar\",\"bar\":\"baz\",\"stray_words\":\"thisisstray\"}\n"


def test_parse_csv_default_arguments(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = "foo,bar,baz";
    $MSG = parse_csv(custom_message);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "foo,bar,baz\n"


def test_parse_csv_optional_arg_columns(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = "foo,bar,baz";
    cols = ["1st","2nd","3rd"];
    $MSG = parse_csv(custom_message, columns=cols);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"1st":"foo","2nd":"bar","3rd":"baz"}\n'


def test_parse_csv_optional_arg_delimiters(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = "foo bar,baz.tik;tak!toe";
    $MSG = parse_csv(custom_message, delimiter=" ,.");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == 'foo,bar,baz,tik;tak!toe\n'


def test_parse_csv_optional_arg_non_greedy(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = "foo,bar,baz,tik,tak,toe";
    cols = ["1st","2nd","3rd"];
    $MSG = parse_csv(custom_message, columns=cols, greedy=false);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"1st":"foo","2nd":"bar","3rd":"baz"}\n'


def test_parse_csv_optional_arg_greedy(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = "foo,bar,baz,tik,tak,toe";
    cols = ["1st","2nd","3rd","rest"];
    $MSG = parse_csv(custom_message, columns=cols, greedy=true);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"1st":"foo","2nd":"bar","3rd":"baz","rest":"tik,tak,toe"}\n'


def test_parse_csv_optional_arg_strip_whitespace(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, """
    custom_message = " foo   ,  bar  ,  baz, tik,   tak,    toe   ";
    $MSG = parse_csv(custom_message, delimiter=",", strip_whitespaces=true);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == 'foo,bar,baz,tik,tak,toe\n'


def test_parse_csv_dialect(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    custom_message = "\"PTHREAD \\\"support initialized\"";
    $MSG = parse_csv(custom_message, dialect="escape-backslash");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "'PTHREAD \"support initialized'\n"


def test_vars(config, syslog_ng):
    (file_true, file_false) = create_config(
        config,
        filterx_expr_1=r"""
            $logmsg_variable = "foo";
            scope_local_variable = "bar";
            declare pipeline_level_variable = "baz";
        """,
        filterx_expr_2=r"""
            log = otel_logrecord({"body": "foobar", "attributes": {"attribute": 42}});
            js_array = json_array([1, 2, 3, [4, 5, 6]]);
            $MSG = vars();
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"$logmsg_variable":"foo","pipeline_level_variable":"baz","log":{"body":"foobar","attributes":{"attribute":42}},"js_array":[1,2,3,[4,5,6]]}\n'


def test_load_vars(config, syslog_ng):
    (file_true, file_false) = create_config(
        config,
        filterx_expr_1=r"""
            my_vars = {
                "$" + "logmsg_variable": "foo",  # "$" + "...": workaround for templating
                "pipeline_level_variable": "baz",
                "log": {
                    "body": "foobar",
                    "attributes": {
                        "attribute": 42
                    }
                },
                "js_array": [1, 2, 3, [4, 5, 6]]
            };
            load_vars(my_vars);
        """,
        filterx_expr_2=r"""
            $MSG = {
                "$" + "logmsg_variable": $logmsg_variable,  # "$" + "...": workaround for templating
                "pipeline_level_variable": pipeline_level_variable,
                "log": log,
                "js_array": js_array
            };
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"$logmsg_variable":"foo","pipeline_level_variable":"baz","log":{"body":"foobar","attributes":{"attribute":42}},"js_array":[1,2,3,[4,5,6]]}\n'


def test_macro_caching(config, syslog_ng):
    (file_true, file_false) = create_config(
        config,
        filterx_expr_1=r"""
            $MSG = {"1": {}, "2": {}, "3": {}, "4": {}};

            $MSG["1"].SEVERITY = $SEVERITY;
            $MSG["1"].FACILITY = $FACILITY;

            $MSG["2"].SEVERITY = $SEVERITY;
            $MSG["2"].FACILITY = $FACILITY;
        """,
        filterx_expr_2=r"""
            $MSG["3"].SEVERITY = $SEVERITY;
            $MSG["3"].FACILITY = $FACILITY;

            $MSG["4"].SEVERITY = $SEVERITY;
            $MSG["4"].FACILITY = $FACILITY;
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    output = json.loads(file_true.read_log())
    assert output["1"] == output["2"] == output["3"] == output["4"] == {"SEVERITY": "notice", "FACILITY": "user"}


def test_unset_empties_invalid_utf8(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            invalid_utf8 = "ba\xC080az";
            dict = {"foo":invalid_utf8};
            unset_empties(dict, targets=["baz"]);
            $MSG = dict;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()


def test_unset_empties_invalid_utf8_target(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            dict = {};
            unset_empties(dict, targets=["b\xC080az"], recursive=true);
            $MSG = dict;
    """,
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_unset_empties(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            dict = {"foo": "", "bar": "-", "baz": "N/A", "almafa": null, "kortefa": {"a":{"s":{"d":{}}}}, "szilvafa": [[[]]]};
            defaults_dict = dict;
            explicit_dict = dict;
            no_defaults_dict = dict;
            target_dict = dict;
            ignorecase_dict = dict;
            replacement_dict = dict;
            unset_empties(defaults_dict, recursive=false);
            unset_empties(explicit_dict, recursive=true);
            unset_empties(no_defaults_dict, targets=["n/a", "-"], recursive=true, ignorecase=true);
            unset_empties(target_dict, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=false);
            unset_empties(ignorecase_dict, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=true);
            unset_empties(replacement_dict, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=true, replacement="do");

            list = ["", "-", "N/A", null, {"a":{"s":{"d":{}}}}, [[[]]]];
            defaults_list = list;
            explicit_list = list;
            no_defaults_list = list;
            target_list = list;
            ignorecase_list = list;
            replacement_list = list;
            unset_empties(defaults_list, recursive=false);
            unset_empties(explicit_list, recursive=true);
            unset_empties(no_defaults_list, targets=["n/a", "-"], recursive=true, ignorecase=true);
            unset_empties(target_list, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=false);
            unset_empties(ignorecase_list, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=true);
            unset_empties(replacement_list, targets=["n/a", "-", null, "", {}, []], recursive=true, ignorecase=true, replacement="do");

            $MSG = [
                    defaults_dict,
                    explicit_dict,
                    no_defaults_dict,
                    target_dict,
                    ignorecase_dict,
                    replacement_dict,
                    defaults_list,
                    explicit_list,
                    no_defaults_list,
                    target_list,
                    ignorecase_list,
                    replacement_list
                    ];
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()

    exp = (
        r"""["""
        r"""{"bar":"-","baz":"N\/A","kortefa":{"a":{"s":{"d":{}}}},"szilvafa":[[[]]]}"""
        r""",{"bar":"-","baz":"N\/A"}"""
        r""",{"foo":"","almafa":null,"kortefa":{"a":{"s":{"d":{}}}},"szilvafa":[[[]]]}"""
        r""",{"baz":"N\/A"}"""
        r""",{}"""
        r""",{"foo":"do","bar":"do","baz":"do","almafa":"do","kortefa":{"a":{"s":{"d":"do"}}},"szilvafa":[["do"]]}"""
        r""",["-","N\/A",{"a":{"s":{"d":{}}}},[[[]]]]"""
        r""",["-","N\/A"]"""
        r""",["",null,{"a":{"s":{"d":{}}}},[[[]]]]"""
        r""",["N\/A"]"""
        r""",[]"""
        r""",["do","do","do","do",{"a":{"s":{"d":"do"}}},[["do"]]]"""
        r"""]"""
        """\n"""
    )

    assert file_true.read_log() == exp


def test_null_coalesce_use_default_on_null(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        x = null;
        y = "bar";
        $MSG = x ?? y;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "bar\n"


def test_nullv_coalesce_assignment(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        x = null;
        y = "bar";
        obj = json();
        obj.a =?? x;
        obj.b =?? y;
        obj.b =?? nonexistent;

        $MSG =?? y;
        $MSG =?? x;
        $MSG =?? nonexistent;
        $MSG += string(obj);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == 'bar{"b":"bar"}\n'


def test_null_coalesce_use_default_on_error_and_supress_error(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        y = "bar";
        $MSG = len(3.14) ?? y; # in-line expression evaluation is mandatory. the error would be propagated other way
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "bar\n"


def test_null_coalesce_get_happy_paths(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        key = "bar";
        $MSG = {};

        $MSG.a = data[key] ?? def;
        $MSG.b = key ?? def;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"a":"2","b":"bar"}\n'


def test_null_coalesce_get_subscript_error(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        key = "missing_key";
        $MSG = data[key] ?? def;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "default\n"


def test_null_coalesce_use_nested_coalesce(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        key1 = "missing_key1";
        key2 = "missing_key2";
        $MSG = data[key1] ?? data[key2] ?? def;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "default\n"


def test_null_coalesce_use_nested_coalesce_return_mid_match(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        key1 = "missing_key1";
        key2 = "baz";
        $MSG = data[key1] ?? data[key2] ?? def;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "3\n"


def test_null_coalesce_do_not_supress_last_error(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        key1 = "missing_key1";
        key2 = "missing_key2";
        key3 = "missing_key3";
        $MSG = data[key1] ?? data[key2] ?? data[key3];
    """,
    )
    syslog_ng.start(config)

    assert file_false.get_stats()["processed"] == 1
    assert "processed" not in file_true.get_stats()


def test_null_coalesce_precedence_versus_ternary(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        data = {"foo":"1", "bar":"2", "baz":"3"};
        def = "default";
        $MSG = {};

        # according to c# and python null coalesce have higher precedence

        # a = ( false ?? isset(data["foo"]) ) ? data["foo"] : def;
        $MSG.a = false ?? isset(data["foo"]) ? data["foo"] : def;

        # b = true ? ( data["wrong"] ?? data["bar"] ) : def;
        $MSG.b = true ? data["wrong"] ?? data["bar"] : def;

        $MSG.c = data["foo"] ? data["bar"] ?? data["baz"] : def;

        # $MSG.d = false ? ( data["foo"] ?? data["bar"] ) : ( data["wrong"] ?? data["baz"] ) ;
        $MSG.d = false ? data["foo"] ?? data["bar"] : data["wrong"] ?? data["baz"];

        # ternary default match value
        $MSG.e = data["wrong"] ?? data["foo"] ? : def;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"a":"default","b":"2","c":"2","d":"3","e":"1"}\n'


def test_slash_string_features(config, syslog_ng):
    cfg = r"""
            $MSG = {};
            $MSG.base = /foo bar/;
            $MSG.line_break = /foo
bar/;
            $MSG.joint_lines = /foo \
bar/;
            ## escaped characters
            $MSG.escaped_backslash = /foo\\bar/;
            $MSG.escaped_slash = /foo\/bar/;
            $MSG.non_escaped_single_quotes = /foo'bar/;
            $MSG.non_escaped_double_quotes = /foo"bar/;
            $MSG.escaped_non_special = /foo\dbar/;

            ## special characters
            $MSG.new_line = /foo\nbar/;
            $MSG.tab = /foo\tbar/;
            $MSG.carrige_return = /foo\rbar/;
            $MSG.vertical_tab = /foo\vbar/;
            $MSG.form_feed = /foo\fbar/;
            $MSG.backspace = /foo\bbar/;
            $MSG.alert = /foo\abar/;

            ##
            $MSG.hexadecimal_value = /foo\x40bar/;
            $MSG.octal_value = /foo\o100bar/;
        """

    (file_true, file_false) = create_config(
        config, cfg,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"base":"foo bar","""
        r""""line_break":"foo\nbar","""
        r""""joint_lines":"foo bar","""
        r""""escaped_backslash":"foo\\bar","""
        r""""escaped_slash":"foo\/bar","""
        r""""non_escaped_single_quotes":"foo'bar","""
        r""""non_escaped_double_quotes":"foo\"bar","""
        r""""escaped_non_special":"foo\\dbar","""
        r""""new_line":"foo\nbar","""
        r""""tab":"foo\tbar","""
        r""""carrige_return":"foo\rbar","""
        r""""vertical_tab":"foo\u000bbar","""
        r""""form_feed":"foo\fbar","""
        r""""backspace":"foo\bbar","""
        r""""alert":"foo\u0007bar","""
        r""""hexadecimal_value":"foo@bar","""
        r""""octal_value":"foo@bar"}""" + "\n"
    )
    res = file_true.read_log()
    assert res == exp


def test_regexp_subst(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        $MSG = {};
        $MSG.single = regexp_subst("foobarbaz","o","");
        $MSG.empty_string = regexp_subst("","a","!");
        $MSG.empty_pattern = regexp_subst("foobarbaz","","!");
        $MSG.zero_length_match = regexp_subst("foobarbaz","u*","!");
        $MSG.orgrp = regexp_subst("foobarbaz", "(fo|az)", "!");
        $MSG.single_global = regexp_subst("foobarbaz","o","", global=true);
        $MSG.empty_string_global = regexp_subst("","a","!", global=true);
        $MSG.empty_pattern_global = regexp_subst("foobarbaz","","!", global=true);
        $MSG.zero_length_match_global = regexp_subst("foobarbaz","u*","!", global=true);
        $MSG.orgrp_global = regexp_subst("foobarbaz", "(fo|az)", "!", global=true);
        $MSG.ignore_case_control = regexp_subst("FoObArBaz", "(o|a)", "!", global=true);
        $MSG.ignore_case = regexp_subst("FoObArBaz", "(o|a)", "!", ignorecase=true, global=true);
        $MSG.groups_off = regexp_subst("25-02-2022", /(\d{2})-(\d{2})-(\d{4})/, "\\3-\\2-\\1", groups=false);
        $MSG.groups_on = regexp_subst("25-02-2022", /(\d{2})-(\d{2})-(\d{4})/, "\\3-\\2-\\1");
        $MSG.mixed_grps = regexp_subst("25-02-2022", /(\d{2})-(\d{2})-(\d{4})/, "foo:\\3-\\2-\\1:bar:baz");
        $MSG.multi_digit_grps = regexp_subst("010203040506070809101112", /(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/, "\\10-\\11-\\12");
        $MSG.prefixing_zeros = regexp_subst("foobar", /^(.*)$/, "\\001012345");
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"single":"fobarbaz","""
        r""""empty_string":"","""
        r""""empty_pattern":"!foobarbaz!","""
        r""""zero_length_match":"!foobarbaz!","""
        r""""orgrp":"!obarbaz","""
        r""""single_global":"fbarbaz","""
        r""""empty_string_global":"","""
        r""""empty_pattern_global":"!f!o!o!b!a!r!b!a!z!","""
        r""""zero_length_match_global":"!f!o!o!b!a!r!b!a!z!","""
        r""""orgrp_global":"!obarb!","""
        r""""ignore_case_control":"F!ObArB!z","""
        r""""ignore_case":"F!!b!rB!z","""
        r""""groups_off":"\\3-\\2-\\1","""
        r""""groups_on":"2022-02-25","""
        r""""mixed_grps":"foo:2022-02-25:bar:baz","""
        r""""multi_digit_grps":"10-11-12","""
        r""""prefixing_zeros":"foobar012345"}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_regexp_subst_all_args_are_mandatory(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
        $MSG = regexp_subst("foobarbaz", "(fo|az)");
    """,
    )
    with pytest.raises(Exception):
        syslog_ng.start(config)


def test_add_operator_for_base_types(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            $MSG = {};
            $MSG.string = ${values.str} + "bar" + "baz";
            $MSG.bytes = string(bytes("\xCA") + bytes("\xFE"));
            $MSG.datetime_integer = string(strptime("2000-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%S%z") + 3600000000);
            $MSG.datetime_double = string(strptime("2000-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%S%z") + 3600.0);
            $MSG.integer_integer = 3 + 4 + 5;
            $MSG.integer_double = 3 + 0.5;
            $MSG.double_integer = 3.5 + 2;
            $MSG.double_double = 3.14 + 0.86;
            js1 = ["foo","bar"];
            js2 = ["baz","other"];
            $MSG.list_list = js1 + js2;
            dict1 = {"foo":"bar"};
            dict2 = {"baz":"other"};
            $MSG.dict_dict = dict1 + dict2;
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"string":"stringbarbaz","""
        r""""bytes":"cafe","""
        r""""datetime_integer":"2000-01-01T01:00:00.000+00:00","""
        r""""datetime_double":"2000-01-01T01:00:00.000+00:00","""
        r""""integer_integer":12,"""
        r""""integer_double":3.5,"""
        r""""double_integer":5.5,"""
        r""""double_double":4.0,"""
        r""""list_list":["foo","bar","baz","other"],"""
        r""""dict_dict":{"foo":"bar","baz":"other"}}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_flatten(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            dict = {"top_level_field":42,"top_level_dict":{"inner_field":1337,"inner_dict":{"inner_inner_field":1}}};

            default_separator = dict;
            custom_separator = dict;

            flatten(default_separator);
            flatten(custom_separator, separator="->");

            $MSG = [default_separator, custom_separator];
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '[' \
        '{"top_level_field":42,"top_level_dict.inner_field":1337,"top_level_dict.inner_dict.inner_inner_field":1},' \
        '{"top_level_field":42,"top_level_dict->inner_field":1337,"top_level_dict->inner_dict->inner_inner_field":1}' \
        ']\n'


def test_add_operator_for_generators(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            $MSG = {};
            js1 = ["foo","bar"];
            js2 = ["baz","other"];
            $MSG.list_var_gen = js1 + ["baz1","other1"];
            $MSG.list_gen_var = ["foo2", "bar2"] + js2;
            $MSG.list_gen_gen = ["foo3", "bar3"] + ["baz3", "other3"];
            dict1 = {"foo":{"bar":"baz"}};
            dict2 = {"tik":{"tak":"toe"}};
            $MSG.dict_var_gen = dict1 + {"tik1":{"tak1":"toe1"}};
            $MSG.dict_gen_var = {"foo2":{"bar2":"baz2"}} + dict2;
            $MSG.dict_gen_gen = {"foo3":{"bar3":"baz3"}} + {"tik3":{"tak3":"toe3"}};
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"list_var_gen":["foo","bar","baz1","other1"],"""
        r""""list_gen_var":["foo2","bar2","baz","other"],"""
        r""""list_gen_gen":["foo3","bar3","baz3","other3"],"""
        r""""dict_var_gen":{"foo":{"bar":"baz"},"tik1":{"tak1":"toe1"}},"""
        r""""dict_gen_var":{"foo2":{"bar2":"baz2"},"tik":{"tak":"toe"}},"""
        r""""dict_gen_gen":{"foo3":{"bar3":"baz3"},"tik3":{"tak3":"toe3"}}}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_plus_equal_grammar_rules(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            $MSG = {};
            js1 = ["foo","bar"];
            js2 = ["baz","other"];

            a = 3;
            a += 2;
            $MSG.var_int = a;

            b = "foo";
            b += "bar";
            $MSG.var_string = b;

            c = 0.44;
            c += 0.58;
            $MSG.var_double = c;

            d = strptime("2000-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%S%z");
            d += 3600000000;
            $MSG.var_datetime_integer = string(d);

            e = strptime("2000-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%S%z");
            e += 3600.000000;
            $MSG.var_datetime_double = string(e);

            $MSG.attr = "tik";
            $MSG.attr += "tak";

            $MSG["subs"] = "bar";
            $MSG["subs"] += "baz";

            $MSG["sub_gen_var"] = ["control"];
            $MSG["sub_gen_var"] += js2;
            $MSG["sub_gen_var"] += ["wtf", "happened"];

            $MSG.attr_gen_var = ["some", "basic"];
            $MSG.attr_gen_var += js1;
            $MSG.attr_gen_var += ["and"];
            $MSG.attr_gen_var += ["add", "to", "plus"];
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"var_int":5,"""
        r""""var_string":"foobar","""
        r""""var_double":1.02,"""
        r""""var_datetime_integer":"2000-01-01T01:00:00.000+00:00","""
        r""""var_datetime_double":"2000-01-01T01:00:00.000+00:00","""
        r""""attr":"tiktak","""
        r""""subs":"barbaz","""
        r""""sub_gen_var":["control","baz","other","wtf","happened"],"""
        r""""attr_gen_var":["some","basic","foo","bar","and","add","to","plus"]}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_get_sdata(config, syslog_ng):
    file_true = config.create_file_destination(file_name="dest-true.log", template="'$MSG\n'")
    file_false = config.create_file_destination(file_name="dest-false.log", template="'$MSG\n'")

    raw_conf = f"""
@version: {config.get_version()}

options {{ stats(level(1)); }};

source genmsg {{
    example-msg-generator(
        num(1)
        template("[Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-13c6-6b16 sid=5214bde6 user=root][anotherSDID@32473 iut=4 eventSource=Application eventID=1012]")
    );
}};

destination dest_true {{
    {render_statement(file_true)};
}};

destination dest_false {{
    {render_statement(file_false)};
}};

parser my_sdata_parser {{
  sdata-parser();
}};

log {{
    source(genmsg);
    if {{
        parser(my_sdata_parser);
        filterx {{ {"$MSG = {}; $MSG.got_sdata = get_sdata();"} \n}};
        destination(dest_true);
    }} else {{
        destination(dest_false);
    }};
}};
"""
    config.set_raw_config(raw_conf)

    syslog_ng.start(config)

    assert json.loads(file_true.read_log()) == {
        "got_sdata": {
            "anotherSDID@32473": {
                "iut": "4",
                "eventSource": "Application",
                "eventID": "1012",
            },
            "Originator@6876": {
                "sub": "Vimsvc.ha-eventmgr",
                "opID": "esxui-13c6-6b16",
                "sid": "5214bde6",
                "user": "root",
            },
        },
    }


def test_list_range_check_with_nulls(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            $MSG = json();
            js1 = json_array([null]);
            js2 = json_array([null, "bar"]);
            $MSG.caseA = js1[0];
            $MSG.caseB = js2[0];
            $MSG.caseC = js2[1];
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"caseA":null,"caseB":null,"caseC":"bar"}\n'


def test_list_range_check_out_of_range(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
            $MSG = json();
            js1 = json_array([null, "bar"]);
            $MSG.caseA = js1[2];
        """,
    )
    syslog_ng.start(config)
    assert file_false.get_stats()["processed"] == 1
    assert file_false.read_log() == "foobar\n"


def test_drop(config, syslog_ng):
    file_true = config.create_file_destination(file_name="dest-true.log", template="'$MSG\n'")
    file_false = config.create_file_destination(file_name="dest-false.log", template="'$MSG\n'")

    raw_conf = f"""
@version: {config.get_version()}

options {{ stats(level(1)); }};

source genmsg {{
    example-msg-generator(num(1) template("foo"));
    example-msg-generator(num(1) template("bar"));
}};

destination dest_true {{
    {render_statement(file_true)};
}};

destination dest_false {{
    {render_statement(file_false)};
}};

log {{
    source(genmsg);
    if {{
        filterx {{ {"if ($MSG =~ 'foo') {drop;};"} \n}};
        destination(dest_true);
    }} else {{
        destination(dest_false);
    }};
}};
"""
    config.set_raw_config(raw_conf)

    syslog_ng.start(config)

    assert "processed" in file_true.get_stats()
    assert file_true.get_stats()["processed"] == 1
    assert file_true.read_log() == 'bar\n'
    assert syslog_ng.wait_for_message_in_console_log("filterx rule evaluation result; result='explicitly dropped'") != []


def test_done(config, syslog_ng):
    (file_true, file_false) = create_config(
        config,
        msg="foo",
        filterx_expr_1=r"""
            if ($MSG =~ 'foo') {
              declare var_wont_change = true;
              done;
              var_wont_change = false; # This will be skipped
            };
        """,
        filterx_expr_2=r"""
            $MSG = vars();
        """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"$MESSAGE":"foo","var_wont_change":true}\n'


def test_parse_xml(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    custom_message = "<a><b attr=\"attr_val\">c</b><b>e</b></a>";
    $MSG = json(parse_xml(custom_message));
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == "{\"a\":{\"b\":[{\"@attr\":\"attr_val\",\"#text\":\"c\"},\"e\"]}}\n"


def test_parse_windows_eventlog_xml(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    xml = "
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='EventCreate'/>
                <EventID Qualifiers='0'>999</EventID>
                <Version>0</Version>
                <Level>2</Level>
                <Task>0</Task>
                <Opcode>0</Opcode>
                <Keywords>0x80000000000000</Keywords>
                <TimeCreated SystemTime='2024-01-12T09:30:12.1566754Z'/>
                <EventRecordID>934</EventRecordID>
                <Correlation/>
                <Execution ProcessID='0' ThreadID='0'/>
                <Channel>Application</Channel>
                <Computer>DESKTOP-2MBFIV7</Computer>
                <Security UserID='S-1-5-21-3714454296-2738353472-899133108-1001'/>
            </System>
            <RenderingInfo Culture='en-US'>
                <Message>foobar</Message>
                <Level>Error</Level>
                <Task></Task>
                <Opcode>Info</Opcode>
                <Channel></Channel>
                <Provider></Provider>
                <Keywords>
                    <Keyword>Classic</Keyword>
                </Keywords>
            </RenderingInfo>
            <EventData>
                <Data Name='param1'>foo</Data>
                <Data Name='param2'>bar</Data>
            </EventData>
        </Event>
    ";
    $MSG = json(parse_windows_eventlog_xml(xml));
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert json.loads(file_true.read_log()) == {
        "Event": {
            "@xmlns": "http://schemas.microsoft.com/win/2004/08/events/event",
            "System": {
                "Provider": {"@Name": "EventCreate"},
                "EventID": {"@Qualifiers": "0", "#text": "999"},
                "Version": "0",
                "Level": "2",
                "Task": "0",
                "Opcode": "0",
                "Keywords": "0x80000000000000",
                "TimeCreated": {"@SystemTime": "2024-01-12T09:30:12.1566754Z"},
                "EventRecordID": "934",
                "Correlation": "",
                "Execution": {"@ProcessID": "0", "@ThreadID": "0"},
                "Channel": "Application",
                "Computer": "DESKTOP-2MBFIV7",
                "Security": {"@UserID": "S-1-5-21-3714454296-2738353472-899133108-1001"},
            },
            "RenderingInfo": {
                "@Culture": "en-US",
                "Message": "foobar",
                "Level": "Error",
                "Task": "",
                "Opcode": "Info",
                "Channel": "",
                "Provider": "",
                "Keywords": {"Keyword": "Classic"},
            },
            "EventData": {
                "Data": {
                    "param1": "foo",
                    "param2": "bar",
                },
            },
        },
    }


def test_startswith_endswith_includes(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    result = json();
    if (startswith($MSG, ["dummy_prefix", "foo"]))
    {
        result.startswith_foo = true;
    };
    bar_var = "bar";
    if (includes($MSG, bar_var, ignorecase=true))
    {
        result.contains_bar = true;
    };
    baz_var = "baz";
    baz_list = ["dummy_suffix", baz_var];
    if (endswith($MSG, baz_list, ignorecase=true))
    {
        result.endswith_baz = true;
    };
    log_msg_value = ${values.str};
    if (includes(log_msg_value, log_msg_value))
    {
        result.works_with_message_value = true;
    };
    $MSG = json();
    $MSG = result;
    """, msg="fooBARbAz",
    )
    syslog_ng.start(config)

    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"startswith_foo":true,"contains_bar":true,"endswith_baz":true,"works_with_message_value":true}\n'


def test_parse_cef(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    custom_message = "CEF:0|KasperskyLab|SecurityCenter|13.2.0.1511|KLPRCI_TaskState|Completed successfully|1|foo=foo\\=bar bar=bar\\=baz baz=test";
    $MSG = json(parse_cef(custom_message));
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"version":"0","""
        r""""device_vendor":"KasperskyLab","""
        r""""device_product":"SecurityCenter","""
        r""""device_version":"13.2.0.1511","""
        r""""device_event_class_id":"KLPRCI_TaskState","""
        r""""name":"Completed successfully","""
        r""""agent_severity":"1","""
        r""""extensions":{"""
        r""""foo":"foo=bar","""
        r""""bar":"bar=baz","""
        r""""baz":"test"}"""
        r"""}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_parse_leef(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    custom_message = "LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|src=192.0.2.0 dst=172.50.123.1 sev=5cat=anomaly srcPort=81 dstPort=21 usrName=joe.black";
    $MSG = json(parse_leef(custom_message));
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"version":"1.0","""
        r""""vendor":"Microsoft","""
        r""""product_name":"MSExchange","""
        r""""product_version":"4.0 SP1","""
        r""""event_id":"15345","""
        r""""extensions":{"""
        r""""src":"192.0.2.0","""
        r""""dst":"172.50.123.1","""
        r""""sev":"5cat=anomaly","""
        r""""srcPort":"81","""
        r""""dstPort":"21","""
        r""""usrName":"joe.black"}"""
        r"""}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_proper_generation_counter(config, syslog_ng):
    file_true = config.create_file_destination(file_name="dest-true.log", template="'$MSG\n'")
    file_false = config.create_file_destination(file_name="dest-false.log", template="'$MSG\n'")

    raw_conf = f"""
@version: {config.get_version()}

options {{ stats(level(1)); }};

source genmsg {{
    example-msg-generator(num(1) template("dummy message") values("bar" => "bar_value"));
}};

destination dest_true {{
    {render_statement(file_true)};
}};

destination dest_false {{
    {render_statement(file_false)};
}};

log {{
    source(genmsg);
    if {{
        filterx {{
            $foo = "foovalue"; # Could have come from the log message as well, doesn't matter
            $ISODATE; # Special case for macro resolution
            unset(${{values.str}}); # Must come from the log message
        }};

        rewrite {{ set("almafa", value("foo")); }};
        parser  {{ date-parser(format("%Y-%m-%dT%H:%M:%S%z") template("2000-01-01T00:00:00+01:00")); }};
        rewrite {{ set("kortefa", value("values.str")); }};

        filterx {{
            $MSG = {{"from_nvtable": $foo, "from_a_macro": $ISODATE, "unset_then_set": ${{values.str}} ?? "not found"}};
        }};
    destination(dest_true);
    }} else {{
        destination(dest_false);
    }};
}};
"""
    config.set_raw_config(raw_conf)

    syslog_ng.start(config)

    assert "processed" in file_true.get_stats()
    assert file_true.get_stats()["processed"] == 1
    assert file_true.read_log() == '{"from_nvtable":"almafa","from_a_macro":"2000-01-01T00:00:00+01:00","unset_then_set":"kortefa"}\n'


def test_set_fields(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    $MSG = {
        "foo": "foo_exists",
        "bar": "bar_exists",
    };
    set_fields(
        $MSG,
        overrides={
            "foo": [invalid_expr, "foo_override"],
            "baz": "baz_override",
            "almafa": [invalid_expr_1, null],  # Should not have any effect, as there is no valid expr or non-null here.
        },
        defaults={
            "foo": [invalid_expr, "foo_default"],  # Should not have any effect, "foo" is handled by overrides.
            "bar": "bar_default",  # Should not have any effect, "bar" already has value in the dict.
            "almafa": "almafa_default",
            "kortefa": [invalid_expr_1, null],  # Should not have any effect, as there is no valid expr or non-null here.
        }
    );
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    assert file_true.read_log() == '{"foo":"foo_override","bar":"bar_exists","baz":"baz_override","almafa":"almafa_default"}\n'


def test_keys(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    dict = {"foo":{"bar":{"baz":"foobarbaz"}},"tik":{"tak":{"toe":"tiktaktoe"}}};
    $MSG = json();
    $MSG.empty = keys(json());
    $MSG.top_level = keys(dict);
    $MSG.nested = keys(dict["foo"]);
    $MSG.direct_access = keys(dict)[0];
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"empty":[],"""
        r""""top_level":["foo","tik"],"""
        r""""nested":["bar"],"""
        r""""direct_access":"foo"}""" + "\n"
    )
    assert file_true.read_log() == exp


def test_path_lookup(config, syslog_ng):
    (file_true, file_false) = create_config(
        config, r"""
    dummy = "foobar";
    dict = {"foo":{"bar":{"baz":"foobarbaz"}},"tik":{"tak":{"toe":"tiktaktoe"}}};
    list = [[3,2,1],[6,5,4],[9,8,7]];
    mixed = {"foo":[{"tik":[3,2,1]}]};
    $MSG = json();
    $MSG.empty = path_lookup(dummy,[]);
    $MSG.dict = path_lookup(dict,["foo", "bar", "baz"]);
    $MSG.list = path_lookup(list,[-1,0]);
    $MSG.sub_dict = path_lookup(dict, ["foo","bar"]);
    $MSG.mixed = path_lookup(mixed,["foo",0,"tik",-1]);
    """,
    )
    syslog_ng.start(config)

    assert file_true.get_stats()["processed"] == 1
    assert "processed" not in file_false.get_stats()
    exp = (
        r"""{"empty":"foobar","""
        r""""dict":"foobarbaz","""
        r""""list":9,"""
        r""""sub_dict":{"baz":"foobarbaz"},"""
        r""""mixed":1}""" + "\n"
    )
    assert file_true.read_log() == exp
