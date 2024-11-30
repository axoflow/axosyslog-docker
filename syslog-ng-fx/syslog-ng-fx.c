#include "filterx/filterx-parser.h"
#include "resolved-configurable-paths.h"
#include "cfg.h"
#include "apphook.h"

static gboolean display_version = FALSE;
static gboolean display_module_registry = FALSE;

static GOptionEntry syslogng_fx_options[] =
{
  { "version",           'V',         0, G_OPTION_ARG_NONE, &display_version, "Display version number (" SYSLOG_NG_PACKAGE_NAME " " SYSLOG_NG_COMBINED_VERSION ")", NULL },
  { "module-path",         0,         0, G_OPTION_ARG_STRING, &resolved_configurable_paths.initial_module_path, "Set the list of colon separated directories to search for modules, default=" SYSLOG_NG_MODULE_PATH, "<path>" },
  { "module-registry",     0,         0, G_OPTION_ARG_NONE, &display_module_registry, "Display module information", NULL },
#ifdef YYDEBUG
  { "yydebug",           'y',         0, G_OPTION_ARG_NONE, &cfg_parser_debug, "Enable configuration parser debugging", NULL },
#endif
  { NULL },
};



int
main(int argc, char *argv[])
{
  GOptionContext *ctx;
  GError *error = NULL;
  const gchar *text = "{ foo = 'bar'; }";
  gint res = 1;


  ctx = g_option_context_new("syslog-ng-fx");
  g_option_context_add_main_entries(ctx, syslogng_fx_options, NULL);
  if (!g_option_context_parse(ctx, &argc, &argv, &error))
    {
      fprintf(stderr, "Error parsing command line arguments: %s\n", error ? error->message : "Invalid arguments");
      g_error_free(error);
      g_option_context_free(ctx);
      return 1;
    }
  g_option_context_free(ctx);
  fprintf(stderr, "huhha\n");


  app_startup();
  configuration = cfg_new_snippet();
  CfgLexer *lexer = cfg_lexer_new_buffer(configuration, text, strlen(text));

  configuration->lexer = lexer;
  cfg_set_global_paths(configuration);

  gpointer result;
  if (!cfg_parser_parse(&filterx_parser, lexer, &result, NULL))
    {
      fprintf(stderr, "Error parsing filterx expression\n");
      goto exit;
    }

  res = 0;
  filterx_expr_unref(result);
exit:
  cfg_free(configuration);
  configuration = NULL;
  app_shutdown();
  return res;
}
