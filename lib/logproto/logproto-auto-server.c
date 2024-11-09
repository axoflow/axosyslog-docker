/*
 * Copyright (c) 2024 Balázs Scheidler <balazs.scheidler@axoflow.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */
#include "logproto-auto-server.h"
#include "logproto-text-server.h"
#include "logproto-framed-server.h"
#include "messages.h"

enum
{
  LPAS_FAILURE,
  LPAS_NEED_MORE_DATA,
  LPAS_SUCCESS,
};

typedef struct _LogProtoAutoServer
{
  LogProtoServer super;

  gboolean tls_detected;
  gboolean haproxy_detected;
} LogProtoAutoServer;

static LogProtoServer *
_construct_detected_proto(LogProtoAutoServer *self, const gchar *detect_buffer, gsize detect_buffer_len)
{
  gint fd = self->super.transport_stack.fd;

  if (g_ascii_isdigit(detect_buffer[0]))
    {
      msg_debug("Auto-detected octet-counted-framing on RFC6587 connection, using framed protocol",
                evt_tag_int("fd", fd));
      return log_proto_framed_server_new(NULL, self->super.options);
    }
  if (detect_buffer[0] == '<')
    {
      msg_debug("Auto-detected non-transparent-framing on RFC6587 connection, using simple text protocol",
                evt_tag_int("fd", fd));
    }
  else
    {
      msg_debug("Unable to detect framing on RFC6587 connection, falling back to simple text transport",
                evt_tag_int("fd", fd),
                evt_tag_mem("detect_buffer", detect_buffer, detect_buffer_len));
    }
  return log_proto_text_server_new(NULL, self->super.options);
}

static gint
_is_tls_client_hello(const gchar *buf, gsize buf_len)
{
  /*
   * The first message on a TLS connection must be the client_hello, which
   * is a type of handshake record, and it cannot be compressed or
   * encrypted.  A plaintext record has this format:
   *
   *       0      byte    record_type      // 0x16 = handshake
   *       1      byte    major            // major protocol version
   *       2      byte    minor            // minor protocol version
   *     3-4      uint16  length           // size of the payload
   *       5      byte    handshake_type   // 0x01 = client_hello
   *       6      uint24  length           // size of the ClientHello
   *       9      byte    major            // major protocol version
   *      10      byte    minor            // minor protocol version
   *      11      uint32  gmt_unix_time
   *      15      byte    random_bytes[28]
   *              ...
   */
  if (buf_len < 1)
    return LPAS_NEED_MORE_DATA;

  /* 0x16 indicates a TLS handshake */
  if (buf[0] != 0x16)
    return LPAS_FAILURE;

  if (buf_len < 5)
    return LPAS_NEED_MORE_DATA;

  guint32 record_len = (buf[3] << 8) + buf[4];

  /* client_hello is at least 34 bytes */
  if (record_len < 34)
    return LPAS_FAILURE;

  if (buf_len < 6)
    return LPAS_NEED_MORE_DATA;

  /* is the handshake_type 0x01 == client_hello */
  if (buf[5] != 0x01)
    return FALSE;

  if (buf_len < 9)
    return LPAS_NEED_MORE_DATA;

  guint32 payload_size = (buf[6] << 16) + (buf[7] << 8) + buf[8];

  /* The message payload can't be bigger than the enclosing record */
  if (payload_size + 4 > record_len)
    return LPAS_FAILURE;
  return LPAS_SUCCESS;
}

static gint
_is_haproxy_header(const gchar *buf, gsize buf_len)
{
  const gchar proxy_v1_signature[] = { 0x50, 0x52, 0x4F, 0x58, 0x59, 0x20 };
  const gchar proxy_v2_signature[] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

  if (buf_len < sizeof(proxy_v1_signature))
    return LPAS_NEED_MORE_DATA;

  if (memcmp(buf, proxy_v1_signature, sizeof(proxy_v1_signature)) == 0)
    return LPAS_SUCCESS;

  if (buf_len < sizeof(proxy_v2_signature))
    return LPAS_NEED_MORE_DATA;

  if (memcmp(buf, proxy_v2_signature, sizeof(proxy_v2_signature)) != 0)
    return LPAS_FAILURE;

  if (buf_len < sizeof(proxy_v2_signature) + 1)
    return LPAS_NEED_MORE_DATA;

  if ((buf[sizeof(proxy_v2_signature)] & 0xf0) != 0x20)
    return LPAS_FAILURE;
  return LPAS_SUCCESS;
}

static LogProtoPrepareAction
log_proto_auto_server_poll_prepare(LogProtoServer *s, GIOCondition *cond, gint *timeout G_GNUC_UNUSED)
{
  LogProtoAutoServer *self = (LogProtoAutoServer *) s;

  if (log_transport_stack_poll_prepare(&self->super.transport_stack, cond))
    return LPPA_FORCE_SCHEDULE_FETCH;

  if (*cond == 0)
    *cond = G_IO_IN;

  return LPPA_POLL_IO;
}

static LogProtoStatus
log_proto_auto_handshake(LogProtoServer *s, gboolean *handshake_finished, LogProtoServer **proto_replacement)
{
  LogProtoAutoServer *self = (LogProtoAutoServer *) s;
  gchar detect_buffer[16];
  gboolean moved_forward;
  gint rc;

  rc = log_transport_stack_read_ahead(&self->super.transport_stack, detect_buffer, sizeof(detect_buffer), &moved_forward);
  if (rc == 0)
    return LPS_EOF;
  else if (rc < 0)
    {
      if (errno == EAGAIN)
        return LPS_AGAIN;
      return LPS_ERROR;
    }

  if (!self->tls_detected)
    {
      switch (_is_tls_client_hello(detect_buffer, rc))
        {
        case LPAS_NEED_MORE_DATA:
          if (moved_forward)
            return LPS_AGAIN;
          break;
        case LPAS_SUCCESS:
          self->tls_detected = TRUE;
          /* this is a TLS handshake! let's switch to TLS */
          if (log_transport_stack_switch(&self->super.transport_stack, LOG_TRANSPORT_TLS))
            {
              msg_debug("TLS handshake detected, switching to TLS");
              return LPS_AGAIN;
            }
          else
            {
              msg_error("TLS handshake detected, unable to switch to TLS, no tls() options specified");
              return LPS_ERROR;
            }
          break;
        default:
          break;
        }
    }
  if (!self->haproxy_detected)
    {
      switch (_is_haproxy_header(detect_buffer, rc))
        {
        case LPAS_NEED_MORE_DATA:
          if (moved_forward)
            return LPS_AGAIN;
          break;
        case LPAS_SUCCESS:
          self->haproxy_detected = TRUE;
          /* this is a haproxy header */
          if (log_transport_stack_switch(&self->super.transport_stack, LOG_TRANSPORT_HAPROXY))
            {
              msg_debug("HAProxy header detected, switching to haproxy");
              return LPS_AGAIN;
            }
          else
            {
              msg_error("HAProxy header detected, but haproxy transport is not set up");
              return LPS_ERROR;
            }
          break;
        default:
          break;

        }
    }
  *proto_replacement = _construct_detected_proto(self, detect_buffer, rc);
  return LPS_SUCCESS;
}

LogProtoServer *
log_proto_auto_server_new(LogTransport *transport, const LogProtoServerOptions *options)
{
  LogProtoAutoServer *self = g_new0(LogProtoAutoServer, 1);

  /* we are not using our own transport stack, transport is to be passed to
   * the LogProto implementation once we finished with detection */

  log_proto_server_init(&self->super, transport, options);
  self->super.handshake = log_proto_auto_handshake;
  self->super.poll_prepare = log_proto_auto_server_poll_prepare;
  return &self->super;
}
