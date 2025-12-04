import nodemailer from 'nodemailer'
import envVar from '../environment-variables'

type SendPasswordResetEmailArgs = {
  email: string
  token: string
}

const transporter = envVar.email.smtpHost
  ? nodemailer.createTransport({
      host: envVar.email.smtpHost,
      port: envVar.email.smtpPort,
      secure: envVar.email.smtpSecure,
      auth:
        envVar.email.smtpUser && envVar.email.smtpPassword
          ? {
              user: envVar.email.smtpUser,
              pass: envVar.email.smtpPassword,
            }
          : undefined,
    })
  : null

function buildResetUrl(email: string, token: string) {
  const base = (envVar.passwordReset.baseUrl || '').replace(/\/$/, '')
  const params = new URLSearchParams({
    email,
    token,
  })

  return `${base || 'http://localhost:3000'}/reset-password?${params.toString()}`
}

export async function sendPasswordResetEmail({ email, token }: SendPasswordResetEmailArgs) {
  const resetUrl = buildResetUrl(email, token)
  const subject = '重設密碼通知'
  const textBody = [
    '您好：',
    '',
    '我們收到您重設 RTI Forum CMS 密碼的請求。',
    `請點擊以下連結完成密碼重設：${resetUrl}`,
    '',
    `此連結 ${envVar.passwordReset.tokensValidForMins} 分鐘內有效，若您未提出申請請忽略本信。`,
  ].join('\n')

  const htmlBody = `
    <p>您好：</p>
    <p>我們收到您重設 RTI Forum CMS 密碼的請求。</p>
    <p><a href="${resetUrl}" target="_blank" rel="noreferrer">點擊這裡重設密碼</a></p>
    <p>此連結 ${envVar.passwordReset.tokensValidForMins} 分鐘內有效，若您未提出申請請忽略本信。</p>
  `

  const logPayload = {
    severity: 'INFO',
    message: 'Generated password reset link',
    type: 'PASSWORD_RESET',
    email,
    resetUrl,
    timestamp: new Date().toISOString(),
  }

  if (!transporter) {
    console.warn(
      JSON.stringify({
        severity: 'WARN',
        message: 'SMTP 設定不存在，已略過寄送重設密碼信件',
        resetUrl,
      })
    )
    console.log(JSON.stringify({ ...logPayload, delivery: 'console' }))
    return
  }

  try {
    await transporter.sendMail({
      from: envVar.email.from,
      to: email,
      subject,
      text: textBody,
      html: htmlBody,
    })

    console.log(JSON.stringify({ ...logPayload, delivery: 'smtp' }))
  } catch (error) {
    console.error(
      JSON.stringify({
        severity: 'ERROR',
        message: '寄送重設密碼信件失敗',
        type: 'PASSWORD_RESET',
        email,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      })
    )
    throw error
  }
}

