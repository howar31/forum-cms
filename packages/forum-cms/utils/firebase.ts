import admin from 'firebase-admin'
import fs from 'fs'
import path from 'path'
import envVar from '../environment-variables'

let firebaseApp: admin.app.App | null = null

function parseServiceAccount() {
  const rawJson = envVar.firebase.serviceAccountJson?.trim()
  if (rawJson) {
    const filePath = path.isAbsolute(rawJson)
      ? rawJson
      : path.resolve(process.cwd(), rawJson)

    if (!fs.existsSync(filePath)) {
      throw new Error(`Firebase service account file not found: ${filePath}`)
    }

    const fileContent = fs.readFileSync(filePath, 'utf8')
    return JSON.parse(fileContent)
  }

  const rawBase64 = envVar.firebase.serviceAccountBase64?.trim()
  if (rawBase64) {
    const decoded = Buffer.from(rawBase64, 'base64').toString('utf8')
    return JSON.parse(decoded)
  }

  return null
}

function getFirebaseApp() {
  if (firebaseApp) {
    return firebaseApp
  }

  if (admin.apps.length > 0) {
    firebaseApp = admin.apps[0]
    return firebaseApp
  }

  const serviceAccount = parseServiceAccount()

  // If service account JSON is provided, use it (for local development)
  if (serviceAccount) {
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: envVar.firebase.projectId || serviceAccount.project_id,
    })
  } else {
  // Otherwise, use Application Default Credentials (for Cloud Run)
    firebaseApp = admin.initializeApp({
      credential: admin.credential.applicationDefault(),
      projectId: envVar.firebase.projectId,
    })
  }

  return firebaseApp
}

export async function verifyFirebaseIdToken(idToken: string) {
  if (!idToken || typeof idToken !== 'string') {
    throw new Error('Firebase ID token is required')
  }

  const app = getFirebaseApp()
  if (!app) {
    throw new Error('Firebase app is not initialized')
  }
  return admin.auth(app).verifyIdToken(idToken)
}
