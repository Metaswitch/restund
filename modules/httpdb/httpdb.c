/**
 * @file httpdb.c HTTP external database backend
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <re.h>
#include <restund.h>


static struct {
  char url[256];                   // Format string for URL - %s is the URL-encoded user name
  struct curl_slist* headers;      // Headers to set
  pthread_key_t curl;              // Thread-local cURL handle.
  bool uri_workaround;             // Work around URI-encoded username.
  char uri_workaround_realm[256];  // Realm to use for URI workaround.
  char uri_workaround_password[256];  // Password to use for URI workaround.
} server;

// Maximum length of HTTP response to handle.
#define STRING_LEN 1000u

struct string {
  size_t len;
  char data[STRING_LEN + 1];
};

// Get the thread-local curl handle if it exists, and create it if not.
// This code is thread-ready, even though restund is currently
// single-threaded.
static CURL* get_curl(int create)
{
  CURL* curl = pthread_getspecific(server.curl);
  if ((curl == NULL) && create)
  {
    curl = curl_easy_init();
    pthread_setspecific(server.curl, curl);
  }
  return curl;
}

// cURL callback: append the data to the supplied struct string*, and NUL-terminate it.
static size_t write_data(char* ptr, size_t size, size_t nmemb, void* userdata)
{
  size_t bytes = size * nmemb;
  struct string* str = (struct string*)userdata;
  if ((str->len + bytes) > STRING_LEN)
  {
    bytes = STRING_LEN - str->len;
  }

  memcpy(str->data + str->len, ptr, bytes);
  str->len += bytes;
  str->data[str->len] = '\0';

  return bytes;
}

// Parse the response, returning pointer to the MD5 string or NULL.
// Modifies data in-place.
static char* parse_digest_response(char* data)
{
  // Response should look like: {"digest_ha1": "6ba737497395177c5abd6297aae181e1"}
  char* p = strstr(data, "\"digest_ha1\":");

  if (p != NULL)
  {
    p += strlen("\"digest_ha1\":");
    p = strstr(p, "\"");
  }

  if (p != NULL)
  {
    p++;
    char* q = strstr(p, "\"");

    if (q == NULL)
    {
      p = NULL;
    }
    else
    {
      *q = '\0';
    }
  }

  return p;
}

static int get_ha1(const char *username, uint8_t *ha1)
{
  int err = EINVAL;
  const char* username_escaped = NULL;
  bool uri_workaround = false;
  char url[256];
  char errstr[CURL_ERROR_SIZE];
  long status;
  struct string str;
  CURLcode res;
  CURL* curl = get_curl(true);
  str.len = 0;

  if (curl == NULL)
  {
    err = EIO;
    restund_error("httpd: failed to initialize curl");
    return err;
  }

  if (!username || !ha1)
  {
    err = EINVAL;
    return err;
  }

  uri_workaround = (server.uri_workaround && strstr(username, "%40"));

  if (uri_workaround)
  {
    // Don't URI-encode, because it looks like it already is.
    restund_info("httpd: bugged client requesting auth for %s", username);
    username_escaped = username;
  }
  else
  {
    username_escaped = curl_easy_escape(curl, username, 0);
  }

  snprintf(url, sizeof(url), server.url, username_escaped);

  if (!uri_workaround)
  {
    curl_free((char*)username_escaped);
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, server.headers);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errstr);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str);

  res = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

  if (res != CURLE_OK)
  {
    restund_error("httpd: %s (%d)", errstr, (int)res);
    err = EIO;
  }
  else if (status == 404)
  {
    // Not found - this is not an error.
    restund_debug("httpd: user not found");
    err = ENOENT;
  }
  else if (status != 200)
  {
    restund_error("httpd: server returned %d\n%s", (int)status, str.data);
    err = EPROTO;
  }
  else
  {
    char* ha1_str;
    restund_debug("httpd: got %s", str.data);
    ha1_str = parse_digest_response(str.data);

    if (ha1_str == NULL)
    {
      restund_error("httpd: bad response %s", str.data);
      err = EPROTO;
    }
    else
    {
      err = str_hex(ha1, MD5_SIZE, ha1_str);

      if (err)
      {
        restund_error("httpd: bad digest %s", ha1_str);
        err = EPROTO;
      }
      else
      {
        restund_debug("httpd: success");
        err = 0;

        if (uri_workaround)
        {
          // We know the user exists, but the H(A1) value will be
          // useless for auth and message integrity. Instead,
          // require bugged clients to use a fixed password, and
          // compute the hash on the fly.
          err = md5_printf(ha1, "%s:%s:%s",
                           username,
                           server.uri_workaround_realm,
                           server.uri_workaround_password);
        }
      }
    }
  }

  return err;
}

static int module_init(void)
{
  int err = 0;
  char header[512];
  char value[512];
  char buf[1024];

  static struct restund_db db = {
    .allh  = NULL,
    .cnth  = NULL,
    .gha1h = get_ha1,
    .tlogh = NULL,
  };

  server.url[0] = '\0';
  server.headers = NULL;
  server.uri_workaround = false;
  server.uri_workaround_realm[0] = '\0';
  strcpy(server.uri_workaround_password, "password");

  conf_get_str(restund_conf(), "httpdb_url", server.url, sizeof(server.url));
  restund_info("httpdb: configured url %s\n", server.url);

  // restund doesn't allow spaces in config values, so we split it in two.
  if ((conf_get_str(restund_conf(), "httpdb_header", header, sizeof(header)) == 0) &&
      (conf_get_str(restund_conf(), "httpdb_header_value", value, sizeof(value)) == 0))
  {
    snprintf(buf, sizeof(buf), "%s: %s", header, value);
    server.headers = curl_slist_append(server.headers, buf);
    restund_info("httpdb: configured header %s\n", buf);
  }

  conf_get_bool(restund_conf(), "httpdb_uri_workaround", &server.uri_workaround);

  if (server.uri_workaround)
  {
    restund_info("httpd: using URI workaround\n");
    conf_get_str(restund_conf(), "realm", server.uri_workaround_realm, sizeof(server.uri_workaround_realm));
    conf_get_str(restund_conf(), "httpdb_uri_workaround_password", server.uri_workaround_password, sizeof(server.uri_workaround_password));
  }

  err = pthread_key_create(&server.curl, (void(*)(void*))curl_easy_cleanup);
  if (err)
  {
    restund_error("httpd: pthread_key_create: %m\n", err);
    return err;
  }

  // Don't be tempted to test our HTTP connection here, because that
  // would introduce a startup-order dependency.

  restund_db_set_handler(&db);
  restund_debug("httpdb: initialized\n");

  return err;
}

static int module_close(void)
{
  // Clean up this thread's connection now, rather than waiting for
  // pthread_exit.  This is to support use by single-threaded code
  // (e.g., UTs), where pthread_exit is never called.
  CURL* curl = get_curl(false);
  if (curl)
  {
    pthread_setspecific(server.curl, NULL);
    curl_easy_cleanup(curl);
  }

  restund_debug("httpdb: module closed\n");

  return 0;
}

const struct mod_export exports = {
  .name = "httpdb",
  .type = "database client",
  .init = module_init,
  .close = module_close,
};
