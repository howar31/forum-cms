import { isPasswordExpired } from './password-policy'
import {
  isAccountLocked,
  shouldResetFailedAttempts,
  getAccountLockoutData,
  getLoginFailureMessage,
} from './account-lockout'
import { verifyRecaptchaToken } from './recaptcha'
import { GraphQLError } from 'graphql'

const LOGIN_IDENTITY_KEYS = ['identity', 'email', 'username']
const USER_QUERY_FIELDS =
  'id email name loginFailedAttempts accountLockedUntil lastFailedLoginAt passwordUpdatedAt mustChangePassword'

function readIdentityFromSource(source: any): string | undefined {
  if (!source || typeof source !== 'object') {
    return undefined
  }

  for (const key of LOGIN_IDENTITY_KEYS) {
    const value = source[key]
    if (typeof value === 'string' && value.length > 0) {
      return value
    }
  }

  return undefined
}

function extractIdentity(requestContext: any): string | undefined {
  const candidates = [
    requestContext.request?.variables,
    requestContext.contextValue?.req?.body?.variables,
  ]

  for (const candidate of candidates) {
    const identity = readIdentityFromSource(candidate)
    if (identity) {
      return identity
    }
  }

  return undefined
}

function extractRecaptchaToken(requestContext: any): string | undefined {
  // First try to get from HTTP header (preferred method)
  const headerToken =
    requestContext.contextValue?.req?.headers?.['x-recaptcha-token'] ||
    requestContext.request?.http?.headers?.get('x-recaptcha-token')

  if (typeof headerToken === 'string' && headerToken.length > 0) {
    return headerToken
  }

  // Fallback: try to get from GraphQL variables (for backwards compatibility)
  const candidates = [
    requestContext.request?.variables,
    requestContext.contextValue?.req?.body?.variables,
  ]

  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'object') {
      const token = candidate.recaptchaToken
      if (typeof token === 'string' && token.length > 0) {
        return token
      }
    }
  }

  return undefined
}

async function findUserByIdentity(contextValue: any, identity: string | undefined) {
  if (!identity || !contextValue) {
    return null
  }

  const trimmed = identity.trim()
  if (!trimmed) {
    return null
  }

  const queryArgs = {
    query: USER_QUERY_FIELDS,
  }

  try {
    const user = await contextValue.sudo().query.User.findOne({
      where: { email: trimmed },
      ...queryArgs,
    })

    if (user) {
      return user
    }
  } catch (error) {
    console.error('findUserByIdentity: unique lookup failed', error)
  }

  const alternativeFilters: any[] = [
    { email: { equals: trimmed, mode: 'insensitive' } },
    { name: { equals: trimmed, mode: 'insensitive' } },
  ]

  if (!trimmed.includes('@')) {
    alternativeFilters.push({ email: { startsWith: trimmed, mode: 'insensitive' } })
  }

  try {
    const candidates = await contextValue
      .sudo()
      .query.User.findMany({
        where: { OR: alternativeFilters },
        take: 1,
        ...queryArgs,
      })

    if (Array.isArray(candidates) && candidates.length > 0) {
      return candidates[0]
    }
  } catch (error) {
    console.error('findUserByIdentity: fallback lookup failed', error)
  }

  return null
}

export const createLoginLoggingPlugin = () => {
  return {
    async requestDidStart(requestContext: any) {
      // Capture client IP from request
      const clientIp =
        requestContext.contextValue?.req?.headers?.['x-forwarded-for'] ||
        requestContext.contextValue?.req?.socket?.remoteAddress ||
        requestContext.request?.http?.headers?.get('x-forwarded-for') ||
        ''

      // Check if this is an authentication request or password reset request
      const operationName = requestContext.request?.operationName
      const query = requestContext.request?.query || ''
      const isAuthRequest =
        query.includes('authenticateUserWithPassword') ||
        operationName === 'AuthenticateUserWithPassword'
      const isPasswordResetRequest =
        query.includes('sendUserPasswordResetLink') ||
        operationName === 'SendUserPasswordResetLink'

      // Pre-authentication: Check reCAPTCHA and account lockout status
      // We'll do the check here but store the result to be used in responseForOperation
      // This avoids throwing in requestDidStart which causes a 500 error
      let lockoutError: GraphQLError | null = null
      let recaptchaError: GraphQLError | null = null

      // Verify reCAPTCHA for password reset requests
      if (isPasswordResetRequest) {
        const recaptchaToken = extractRecaptchaToken(requestContext)
        const recaptchaResult = await verifyRecaptchaToken(recaptchaToken, 'forgot_password')

        if (!recaptchaResult.success) {
          recaptchaError = new GraphQLError(recaptchaResult.message || '人機驗證失敗', {
            extensions: {
              code: 'RECAPTCHA_FAILED',
              score: recaptchaResult.score,
            },
          })

          // Log reCAPTCHA failure
          console.log(
            JSON.stringify({
              severity: 'WARNING',
              message: 'reCAPTCHA verification failed for password reset',
              type: 'RECAPTCHA_PASSWORD_RESET_FAILED',
              email: requestContext.request?.variables?.email,
              score: recaptchaResult.score,
              errorCodes: recaptchaResult.errorCodes,
              remoteIp: clientIp,
              timestamp: new Date().toISOString(),
            })
          )
        }
      }

      if (isAuthRequest) {
        // Verify reCAPTCHA token first
        const recaptchaToken = extractRecaptchaToken(requestContext)
        const recaptchaResult = await verifyRecaptchaToken(recaptchaToken, 'login')

        if (!recaptchaResult.success) {
          recaptchaError = new GraphQLError(recaptchaResult.message || '人機驗證失敗', {
            extensions: {
              code: 'RECAPTCHA_FAILED',
              score: recaptchaResult.score,
            },
          })

          // Log reCAPTCHA failure
          console.log(
            JSON.stringify({
              severity: 'WARNING',
              message: 'reCAPTCHA verification failed for login',
              type: 'RECAPTCHA_LOGIN_FAILED',
              identity: extractIdentity(requestContext),
              score: recaptchaResult.score,
              errorCodes: recaptchaResult.errorCodes,
              remoteIp: clientIp,
              timestamp: new Date().toISOString(),
            })
          )
        }

        // Only check account lockout if reCAPTCHA passed
        if (!recaptchaError) {
          const identity = extractIdentity(requestContext)

          if (identity && requestContext.contextValue) {
            try {
              const user = await findUserByIdentity(requestContext.contextValue, identity)

              if (user) {
                // Check if account is locked
                if (isAccountLocked(user)) {
                  const errorMessage = getLoginFailureMessage(user, true)

                  lockoutError = new GraphQLError(errorMessage, {
                    extensions: {
                      code: 'ACCOUNT_LOCKED',
                    },
                  })
                }

                // If lockout period has expired, reset failed attempts
                if (shouldResetFailedAttempts(user)) {
                  await requestContext.contextValue.sudo().db.User.updateOne({
                    where: { id: user.id },
                    data: {
                      loginFailedAttempts: 0,
                      accountLockedUntil: null,
                      lastFailedLoginAt: null,
                    },
                  })
                }
              }
            } catch (error) {
              console.error('Error checking account lockout:', error)
            }
          }
        }
      }

      return {
        async responseForOperation() {
          // Check reCAPTCHA error first
          if (recaptchaError) {
            return {
              http: {
                status: 200,
                headers: new Map([['X-Recaptcha-Failed', 'true']]),
              },
              body: {
                kind: 'single',
                singleResult: {
                  errors: [recaptchaError],
                },
              },
            }
          }

          if (lockoutError) {
            return {
              http: {
                status: 200,
                headers: new Map([['X-Account-Locked', 'true']]),
              },
              body: {
                kind: 'single',
                singleResult: {
                  errors: [lockoutError],
                },
              },
            }
          }
          return null
        },

        async willSendResponse(requestContext: any) {
          const { response, contextValue } = requestContext // Keystone context is in contextValue

          if (
            response.body.kind === 'single' &&
            'singleResult' in response.body
          ) {
            const data = response.body.singleResult.data

            if (data) {
              // Iterate over all keys to find authentication responses
              for (const key of Object.keys(data)) {
                const result = data[key]

                // Check if the result looks like an authentication response
                // It should have either a sessionToken (success)
                // or be of type UserAuthenticationWithPasswordFailure
                if (
                  result &&
                  typeof result === 'object' &&
                  (
                    result.__typename === 'UserAuthenticationWithPasswordSuccess' ||
                    result.__typename === 'UserAuthenticationWithPasswordFailure' ||
                    'sessionToken' in result
                  )
                ) {

                  const isSuccess =
                    result.__typename === 'UserAuthenticationWithPasswordSuccess' ||
                    !!result.sessionToken

                  let extraUserData: any = {};
                  // For failed logins, result.item is undefined, so get email from request variables
                  // KeystoneJS uses 'identity' and 'secret' as variable names, not 'email' and 'password'
                  let userEmail = result.item?.email || extractIdentity(requestContext);

                  // Update lockout data based on authentication result
                  if (contextValue && userEmail) {
                    try {
                      // Find the user to update lockout data
                      const user = await findUserByIdentity(contextValue, userEmail)

                      if (user) {
                        // Calculate lockout data update
                        const lockoutData = getAccountLockoutData(isSuccess, user)

                        // Update user with lockout data
                        await contextValue.sudo().db.User.updateOne({
                          where: { id: user.id },
                          data: lockoutData,
                        })

                        // Prepare extra data for logging
                        const needsPasswordUpdate = isPasswordExpired(user)
                        const updatedUserState = { ...user, ...lockoutData }
                        const isLocked = isAccountLocked(updatedUserState)
                        const failureNotice =
                          !isSuccess && getLoginFailureMessage(updatedUserState, isLocked)

                        extraUserData = {
                          userName: user.name,
                          userEmail: user.email,
                          mustChangePassword: user.mustChangePassword,
                          passwordUpdatedAt: user.passwordUpdatedAt,
                          requiresPasswordChange: needsPasswordUpdate,
                          loginFailedAttempts: isSuccess ? 0 : (lockoutData.loginFailedAttempts || 0),
                          accountLocked: isLocked,
                        };

                        // If account is locked, set header to trigger redirect
                        if (isLocked && requestContext.contextValue?.res) {
                          requestContext.contextValue.res.setHeader('X-Account-Locked', 'true')
                        }

                        if (!isSuccess && failureNotice && requestContext.contextValue?.res) {
                          requestContext.contextValue.res.setHeader(
                            'X-Login-Failure-Message',
                            encodeURIComponent(failureNotice)
                          )
                        }

                        // If user needs to change password, modify the response
                        if (needsPasswordUpdate && requestContext.contextValue?.res) {
                          const res = requestContext.contextValue.res
                          res.setHeader('X-Require-Password-Change', 'true')

                          if (result.__typename === 'UserAuthenticationWithPasswordSuccess' && result.item) {
                            result.item.requirePasswordChange = true
                          }
                        }
                      }
                    } catch (e) {
                      console.error('Error updating lockout data:', e);
                    }
                  } else if (isSuccess && result.item?.id && contextValue) {
                    try {
                      // Fetch the user to get extra fields not requested by the client
                      const user = await contextValue.sudo().db.User.findOne({
                        where: { id: result.item.id },
                        query: 'id name email passwordUpdatedAt mustChangePassword'
                      });

                      if (user) {
                        const needsPasswordUpdate = isPasswordExpired(user)

                        extraUserData = {
                          userName: user.name,
                          userEmail: user.email,
                          mustChangePassword: user.mustChangePassword,
                          passwordUpdatedAt: user.passwordUpdatedAt,
                          requiresPasswordChange: needsPasswordUpdate,
                        };

                        // If user needs to change password, modify the response
                        if (needsPasswordUpdate && requestContext.contextValue?.res) {
                          const res = requestContext.contextValue.res
                          res.setHeader('X-Require-Password-Change', 'true')

                          if (result.__typename === 'UserAuthenticationWithPasswordSuccess' && result.item) {
                            result.item.requirePasswordChange = true
                          }
                        }
                      }
                    } catch (e) {
                      console.error('Error fetching user details for logging:', e);
                    }
                  }

                  const log = {
                    severity: isSuccess ? 'INFO' : 'WARNING',
                    message: isSuccess
                      ? 'User logged in successfully'
                      : 'User login failed',
                    type: 'LOGIN',
                    status: isSuccess ? 'success' : 'failure',
                    timestamp: new Date().toISOString(),
                    remoteIp: clientIp,
                    ...(isSuccess
                      ? {
                        userId: result.item?.id,
                        userName: extraUserData.userName || result.item?.name,
                        userEmail: extraUserData.userEmail || result.item?.email,
                        mustChangePassword: extraUserData.mustChangePassword ?? result.item?.mustChangePassword,
                        passwordUpdatedAt: extraUserData.passwordUpdatedAt ?? result.item?.passwordUpdatedAt,
                        requiresPasswordChange: extraUserData.requiresPasswordChange,
                      }
                      : {
                        failureReason: result.message || 'Unknown error',
                        identity: extractIdentity(requestContext),
                        loginFailedAttempts: extraUserData.loginFailedAttempts,
                        accountLocked: extraUserData.accountLocked,
                      }),
                  }
                  console.log(JSON.stringify(log))
                }
              }
            }
          }
        },
      }
    },
  }
}
