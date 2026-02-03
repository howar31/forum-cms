# Forum CMS

Forum 後台內容管理系統，基於 [Keystone 6](https://keystonejs.com/) 的 monorepo。

## Monorepo 結構

本 repo 使用 Yarn workspaces，包含以下套件：

- **[packages/core](./packages/core)**（`@mirrormedia/lilith-core`）：共用 Keystone 自訂欄位與工具（如 rich-text-editor、filters、access control 等），供 CMS 使用。
- **[packages/forum-cms](./packages/forum-cms)**：Forum CMS 主應用，提供文章、留言、會員、分類、標籤、反應等內容管理與 GraphQL API。

開發流程使用 **husky**、**lint-staged**，在 `git commit` 前會對變更檔案執行 eslint。

## 環境需求

- Node.js >= 22.0.0
- Yarn >= 1.22.0

## 安裝與開發

在專案根目錄安裝依賴（會一併處理各 workspace 的依賴）：

```bash
yarn install
```

修改或開發各套件前，請先在根目錄執行過 `yarn install`，以確保 husky、lint-staged 與 workspace 依賴正確。

## 前端會員登入 API（Firebase）

以下 API 用於前端會員登入（對應 `packages/forum-cms/lists/member.ts`），與 Admin UI 的 User 登入不同。

### GraphQL Endpoint
- `POST /api/graphql`

### 驗證流程（Firebase -> Keystone）
1. 前端用 Firebase Client SDK 登入，取得 `idToken`。
2. 呼叫 `authenticateMemberWithFirebase` 取得會員資料與後端 session token。
3. 後續請求帶 `Authorization: Bearer <sessionToken>`。

### Mutation：authenticateMemberWithFirebase
- 功能：驗證 Firebase ID token、建立/更新 Member、回傳後端 session token。

```
mutation AuthenticateMemberWithFirebase($data: AuthenticateMemberWithFirebaseInput!) {
  authenticateMemberWithFirebase(data: $data) {
    sessionToken
    expiresAt
    member {
      id
      firebaseId
      customId
      name
      nickname
      email
    }
  }
}
```

#### Variables 範例
```
{
  "data": {
    "idToken": "FIREBASE_ID_TOKEN",
    "name": "使用者名稱",
    "nickname": "暱稱",
    "customId": "自訂ID"
  }
}
```

#### 欄位規則（重要）
- `firebaseId` 由 Firebase token 的 `uid` 而來，為唯一鍵。
- `customId` 若未提供，預設為 `uid`。
- `name` / `nickname` 若未提供，依序使用 `Firebase displayName` / `email local-part` / `uid`。
- 若 `customId` 或 `email` 與其他 Firebase 帳號重複，會回錯誤。

### Query：authenticatedMember
- 功能：用後端 session token 取得目前登入會員。
- Header：`Authorization: Bearer <sessionToken>`

```
query AuthenticatedMember {
  authenticatedMember {
    id
    firebaseId
    customId
    name
    nickname
    email
  }
}
```

### 需要的環境變數（後端）
在 `packages/forum-cms` 的環境設定中請提供：
- `FIREBASE_PROJECT_ID`
- `FIREBASE_SERVICE_ACCOUNT_JSON` 或 `FIREBASE_SERVICE_ACCOUNT_BASE64`
- `MEMBER_SESSION_SECRET`
- `MEMBER_SESSION_MAX_AGE`（秒）

## 常見問題

### 在根目錄執行 `yarn install` 時，於 `yarn postinstall` 階段報錯

若錯誤與 `@mirrormedia/lilith-core` 有關，可依序執行：

1. 在 `packages/core` 執行 `yarn build`
2. 回到專案根目錄執行 `yarn install`

以確保本機有建好的 `@mirrormedia/lilith-core` 供其他 package 使用。

### Windows 下安裝時出現與 `postinstall` 相關錯誤

Yarn workspace 與個別 package 的 `postinstall` 在 Windows 上曾有相容性問題，可改為先略過 postinstall 完成安裝，再到需要的 package 手動執行：

1. 在根目錄執行：`set WINDOWS_ONLY=true && yarn install`
2. 進入目標 package 目錄後執行：`set WINDOWS_ONLY=false && yarn postinstall`
