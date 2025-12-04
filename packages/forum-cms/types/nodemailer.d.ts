declare module 'nodemailer' {
  type TransportOptions = Record<string, unknown>
  type SendMailOptions = Record<string, unknown>
  type SentMessageInfo = Record<string, unknown>

  interface Transporter {
    sendMail(mailOptions: SendMailOptions): Promise<SentMessageInfo>
  }

  export function createTransport(options: TransportOptions): Transporter

  const nodemailer: {
    createTransport: typeof createTransport
  }

  export default nodemailer
}

