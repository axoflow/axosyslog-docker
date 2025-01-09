lib_filterx_tests_TESTS		 =              \
		lib/filterx/tests/test_object_primitive	\
		lib/filterx/tests/test_object_message	\
		lib/filterx/tests/test_object_datetime	\
		lib/filterx/tests/test_object_json	\
		lib/filterx/tests/test_object_null	\
		lib/filterx/tests/test_object_string	\
		lib/filterx/tests/test_object_protobuf	\
		lib/filterx/tests/test_object_double	\
		lib/filterx/tests/test_object_boolean	\
		lib/filterx/tests/test_object_integer	\
		lib/filterx/tests/test_object_bytes	\
		lib/filterx/tests/test_filterx_expr	\
		lib/filterx/tests/test_expr_function	\
		lib/filterx/tests/test_expr_comparison \
		lib/filterx/tests/test_expr_condition \
		lib/filterx/tests/test_expr_compound \
		lib/filterx/tests/test_expr_function \
		lib/filterx/tests/test_builtin_functions \
		lib/filterx/tests/test_type_registry \
		lib/filterx/tests/test_func_istype \
		lib/filterx/tests/test_func_unset_empties \
		lib/filterx/tests/test_func_flatten \
		lib/filterx/tests/test_expr_regexp_search	\
		lib/filterx/tests/test_expr_regexp_subst	\
		lib/filterx/tests/test_expr_regexp	\
		lib/filterx/tests/test_expr_null_coalesce	\
		lib/filterx/tests/test_expr_plus	\
		lib/filterx/tests/test_expr_plus_generator \
		lib/filterx/tests/test_expr_plus \
		lib/filterx/tests/test_metrics_labels \
		lib/filterx/tests/test_object_dict_interface \
		lib/filterx/tests/test_func_keys \
		lib/filterx/tests/test_filterx_object \
		lib/filterx/tests/test_func_path_lookup

EXTRA_DIST += lib/filterx/tests/CMakeLists.txt

check_PROGRAMS				+= ${lib_filterx_tests_TESTS}

lib_filterx_tests_test_object_primitive_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_primitive_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_message_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_message_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_datetime_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_datetime_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_json_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_json_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_null_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_null_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_string_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_string_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_filterx_expr_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_filterx_expr_LDADD   = $(TEST_LDADD) $(PREOPEN_SYSLOGFORMAT) $(JSON_LIBS)

lib_filterx_tests_test_expr_comparison_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_comparison_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_condition_CFLAGS = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_condition_LDADD	 = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_compound_CFLAGS = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_compound_LDADD	 = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_builtin_functions_CFLAGS = $(TEST_CFLAGS)
lib_filterx_tests_test_builtin_functions_LDADD = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_bytes_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_bytes_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_protobuf_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_protobuf_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_boolean_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_boolean_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_integer_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_integer_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_double_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_double_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_type_registry_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_type_registry_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_func_istype_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_func_istype_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_func_unset_empties_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_func_unset_empties_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_func_flatten_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_func_flatten_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_function_CFLAGS	= $(TEST_CFLAGS)
lib_filterx_tests_test_expr_function_LDADD	= $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_regexp_search_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_regexp_search_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_regexp_subst_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_regexp_subst_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_regexp_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_regexp_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_null_coalesce_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_null_coalesce_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_plus_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_plus_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_expr_plus_generator_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_expr_plus_generator_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_metrics_labels_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_metrics_labels_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_object_dict_interface_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_object_dict_interface_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_func_keys_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_func_keys_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_filterx_object_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_filterx_object_LDADD   = $(TEST_LDADD) $(JSON_LIBS)

lib_filterx_tests_test_func_path_lookup_CFLAGS  = $(TEST_CFLAGS)
lib_filterx_tests_test_func_path_lookup_LDADD   = $(TEST_LDADD) $(JSON_LIBS)
