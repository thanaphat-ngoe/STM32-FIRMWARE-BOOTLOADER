#include "cmox_crypto.h"

/**
  * @brief  Low-level initialization of the cryptographic library
  * @param  pInitParam Pointer to initialization parameter
  * @retval CMOX_INIT_SUCCESS if successful
  */
cmox_init_retval_t cmox_ll_init(void *pInitParam)
{
	(void)pInitParam;
	return CMOX_INIT_SUCCESS;
}

/**
  * @brief  Low-level de-initialization of the cryptographic library
  * @retval CMOX_INIT_SUCCESS if successful
  */
cmox_init_retval_t cmox_ll_deinit(void)
{
  	return CMOX_INIT_SUCCESS;
}
