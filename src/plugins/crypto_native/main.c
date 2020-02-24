/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>

crypto_native_main_t crypto_native_main;

static void
crypto_native_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			   vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->key_fn[key->alg] == 0)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->key_data))
	return;

      if (cm->key_data[idx] == 0)
	return;

      clib_mem_free_s (cm->key_data[idx]);
      cm->key_data[idx] = 0;
      return;
    }

  vec_validate_aligned (cm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && cm->key_data[idx])
    {
      clib_mem_free_s (cm->key_data[idx]);
    }

  cm->key_data[idx] = cm->key_fn[key->alg] (key);
}

clib_error_t *
crypto_native_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;

  if (clib_cpu_supports_x86_aes () == 0 &&
      clib_cpu_supports_aarch64_aes () == 0)
    return 0;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "native", 100,
				 "Native ISA Optimized Crypto");

#if __x86_64__
  if (clib_cpu_supports_vaes ())
    error = crypto_native_aes_cbc_init_vaes (vm);
  else if (clib_cpu_supports_avx512f ())
    error = crypto_native_aes_cbc_init_avx512 (vm);
  else if (clib_cpu_supports_avx2 ())
    error = crypto_native_aes_cbc_init_avx2 (vm);
  else
    error = crypto_native_aes_cbc_init_sse42 (vm);

  if (error)
    goto error;

  if (clib_cpu_supports_pclmulqdq ())
    {
      if (clib_cpu_supports_vaes ())
	error = crypto_native_aes_gcm_init_vaes (vm);
      else if (clib_cpu_supports_avx512f ())
	error = crypto_native_aes_gcm_init_avx512 (vm);
      else if (clib_cpu_supports_avx2 ())
	error = crypto_native_aes_gcm_init_avx2 (vm);
      else
	error = crypto_native_aes_gcm_init_sse42 (vm);

      if (error)
	goto error;
    }
#endif
#if __aarch64__
  if ((error = crypto_native_aes_cbc_init_neon (vm)))
    goto error;

  if ((error = crypto_native_aes_gcm_init_neon (vm)))
    goto error;
#endif

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_native_key_handler);


error:
  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_native_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */

#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel IA32 Software Crypto Engine",
};
/* *INDENT-ON* */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static clib_error_t *
test_gcm_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  u32 min = 0, max = 65536 + 32;
  u8 *pt1, *ct1, *ct2, *pt2;
  u8 tag1[16], tag2[16], key[32], iv[12];
  int tag_len = 12;

#if 0
  unformat_input_t _line_input, *line_input = &_line_input;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "min %d", &min))
	;
      else if (unformat (line_input, "max %d", &max))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);
#endif

  vlib_cli_output (vm, "min %u max %u", min, max);

  pt1 = clib_mem_alloc (max);
  pt2 = clib_mem_alloc (max);
  ct1 = clib_mem_alloc (max);
  ct2 = clib_mem_alloc (max);

  for (int i = 0; i < max; i++)
    pt1[i] = i;

  for (int i = 0; i < 32; i++)
    key[i] = i * 4;

  for (int i = 0; i < 12; i++)
    iv[i] = 0x80 + i;

  vnet_crypto_key_index_t ki;
  ki = vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_AES_128_GCM, key, 16);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();

  int len = max;
  int out_len;

  for (len = 1; len < 65536; len++)
    {
      u32 *ctt = (u32 *) (ct2 + len);
      u32 *ptt = (u32 *) (pt2 + len);
      u32 *tt = (u32 *) (tag2 + 12);
      int err = 0;

      ctt[0] = ptt[0] = tt[0] = 0xdeadbeef;
      EVP_EncryptInit_ex (ctx, EVP_aes_128_gcm (), 0, 0, 0);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
      EVP_EncryptInit_ex (ctx, 0, 0, key, iv);
      EVP_EncryptUpdate (ctx, ct1, &out_len, pt1, len);
      EVP_EncryptFinal_ex (ctx, ct1 + out_len, &out_len);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, 12, tag1);

      vnet_crypto_op_t op[2];
      vnet_crypto_op_init (op, VNET_CRYPTO_OP_AES_128_GCM_ENC);
      vnet_crypto_op_init (op + 1, VNET_CRYPTO_OP_AES_128_GCM_DEC);

      op[0].src = pt1;
      op[0].dst = ct2;
      op[0].tag = tag2;
      op[1].src = ct1;
      op[1].dst = pt2;
      op[1].tag = tag1;

      op[0].iv = op[1].iv = iv;
      op[0].len = op[1].len = len;
      op[0].aad_len = op[1].aad_len = 0;
      op[0].tag_len = op[1].tag_len = tag_len;
      op[0].key_index = op[1].key_index = ki;

      vnet_crypto_process_ops (vm, op, 2);

      if (memcmp (tag1, tag2, tag_len))
	{
	  vlib_cli_output (vm, "tag1 %U", format_hexdump, tag1, tag_len);
	  vlib_cli_output (vm, "tag2 %U", format_hexdump, tag2, tag_len);
	  err++;
	}

      if (memcmp (ct1, ct2, len))
	{
	  vlib_cli_output (vm, "ct1 %U", format_hexdump, ct1, len);
	  vlib_cli_output (vm, "ct2 %U", format_hexdump, ct2, len);
	  err++;
	}

      if (memcmp (pt1, pt2, len))
	{
	  vlib_cli_output (vm, "pt1 %U", format_hexdump, pt1, len);
	  vlib_cli_output (vm, "pt2 %U", format_hexdump, pt2, len);
	  err++;
	}

      if (op[1].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	err++;

      if (ctt[0] != 0xdeadbeef && ++err)
	vlib_cli_output (vm, "ct 0x%x != 0xdeadbeef", ctt[0]);

      if (ptt[0] != 0xdeadbeef && ++err)
	vlib_cli_output (vm, "pt 0x%x != 0xdeadbeef\n%U", ptt[0],
			 format_hexdump, pt2, len + 4);

      if (tt[0] != 0xdeadbeef && ++err)
	vlib_cli_output (vm, "tt 0x%x != 0xdeadbeef", tt[0]);

      if (err)
	{
	  vlib_cli_output (vm, "len %u status %u", len, op[1].status);
	  goto done;
	}
    }

done:
  vnet_crypto_key_del (vm, ki);
  clib_mem_free (pt1);
  clib_mem_free (pt2);
  clib_mem_free (ct1);
  clib_mem_free (ct2);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_gcm_command, static) = {
  .path = "test gcm",
  .short_help = "test gcm",
  .function = test_gcm_command_fn,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
