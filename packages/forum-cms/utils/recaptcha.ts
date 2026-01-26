import envVar from '../environment-variables'

interface RecaptchaVerifyResponse {
  success: boolean
  score?: number
  action?: string
  challenge_ts?: string
  hostname?: string
  'error-codes'?: string[]
}

interface RecaptchaVerifyResult {
  success: boolean
  score: number
  errorCodes?: string[]
  message?: string
}

/**
 * Verify reCAPTCHA v3 token with Google API
 * @param token - The reCAPTCHA token from frontend
 * @param expectedAction - Optional action name to verify (e.g., 'login', 'forgot_password')
 * @returns Verification result with success status and score
 */
export async function verifyRecaptchaToken(
  token: string | undefined | null,
  expectedAction?: string
): Promise<RecaptchaVerifyResult> {
  // If reCAPTCHA is disabled, always return success
  if (!envVar.recaptcha.enabled) {
    return {
      success: true,
      score: 1.0,
      message: 'reCAPTCHA verification skipped (disabled)',
    }
  }

  // Check if secret key is configured
  if (!envVar.recaptcha.secretKey) {
    console.error(
      JSON.stringify({
        severity: 'ERROR',
        message: 'reCAPTCHA secret key not configured',
        type: 'RECAPTCHA_CONFIG_ERROR',
        timestamp: new Date().toISOString(),
      })
    )
    return {
      success: false,
      score: 0,
      message: 'reCAPTCHA 設定錯誤，請聯繫管理員',
    }
  }

  // Check if token is provided
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return {
      success: false,
      score: 0,
      message: '請完成人機驗證',
    }
  }

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: envVar.recaptcha.secretKey,
        response: token,
      }),
    })

    if (!response.ok) {
      console.error(
        JSON.stringify({
          severity: 'ERROR',
          message: 'reCAPTCHA API request failed',
          type: 'RECAPTCHA_API_ERROR',
          status: response.status,
          timestamp: new Date().toISOString(),
        })
      )
      return {
        success: false,
        score: 0,
        message: '人機驗證服務暫時無法使用，請稍後再試',
      }
    }

    const result: RecaptchaVerifyResponse = await response.json()

    // Log verification result for debugging
    console.log(
      JSON.stringify({
        severity: 'INFO',
        message: 'reCAPTCHA verification result',
        type: 'RECAPTCHA_VERIFY',
        success: result.success,
        score: result.score,
        action: result.action,
        expectedAction,
        hostname: result.hostname,
        errorCodes: result['error-codes'],
        timestamp: new Date().toISOString(),
      })
    )

    if (!result.success) {
      return {
        success: false,
        score: 0,
        errorCodes: result['error-codes'],
        message: '人機驗證失敗，請重新操作',
      }
    }

    // Check action if expected action is provided
    if (expectedAction && result.action !== expectedAction) {
      console.warn(
        JSON.stringify({
          severity: 'WARNING',
          message: 'reCAPTCHA action mismatch',
          type: 'RECAPTCHA_ACTION_MISMATCH',
          expectedAction,
          actualAction: result.action,
          timestamp: new Date().toISOString(),
        })
      )
      return {
        success: false,
        score: result.score ?? 0,
        message: '人機驗證失敗，請重新操作',
      }
    }

    const score = result.score ?? 0
    const threshold = envVar.recaptcha.scoreThreshold

    if (score < threshold) {
      console.warn(
        JSON.stringify({
          severity: 'WARNING',
          message: 'reCAPTCHA score below threshold',
          type: 'RECAPTCHA_LOW_SCORE',
          score,
          threshold,
          action: result.action,
          timestamp: new Date().toISOString(),
        })
      )
      return {
        success: false,
        score,
        message: '偵測到可疑活動，請稍後再試或聯繫管理員',
      }
    }

    return {
      success: true,
      score,
    }
  } catch (error) {
    console.error(
      JSON.stringify({
        severity: 'ERROR',
        message: 'reCAPTCHA verification error',
        type: 'RECAPTCHA_ERROR',
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      })
    )
    return {
      success: false,
      score: 0,
      message: '人機驗證失敗，請稍後再試',
    }
  }
}

/**
 * Check if reCAPTCHA is enabled
 */
export function isRecaptchaEnabled(): boolean {
  return envVar.recaptcha.enabled
}

/**
 * Get reCAPTCHA site key for frontend
 */
export function getRecaptchaSiteKey(): string {
  return envVar.recaptcha.siteKey
}
