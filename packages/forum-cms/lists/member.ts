import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, relationship, checkbox, integer, select, timestamp } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    firebaseId: text({
      label: 'Firebase ID',
      validation: {
        isRequired: true,
      },
      isIndexed: 'unique',
    }),
    customId: text({
      label: '自訂 ID',
      validation: {
        isRequired: true,
      },
      isIndexed: 'unique',
    }),
    name: text({
      label: '姓名',
      validation: { isRequired: true },
    }),
    nickname: text({ label: '暱稱', validation: { isRequired: true } }),
    avatar: text({ label: '頭像', validation: { isRequired: false } }),
    intro: text({ label: '介紹', validation: { isRequired: false } }),
    avatar_image: relationship({
      label: '頭像圖片',
      ref: 'Photo',
    }),
    email: text({
      label: 'Email',
      validation: { isRequired: false },
      isFilterable: true,
      isIndexed: 'unique',
    }),
    is_active: checkbox({
      label: '啟用',
      defaultValue: true,
    }),
    verified: checkbox({
      label: '已驗證',
      defaultValue: false,
    }),
    comment: relationship({
      label: '留言',
      ref: 'Comment.member',
      many: true,
    }),
    member_like: relationship({
      label: '按讚',
      ref: 'Comment.like',
      many: true,
    }),
    posts: relationship({
      label: '文章',
      ref: 'Post.author',
      many: true,
    }),
    reactions: relationship({
      label: '反應',
      ref: 'Reaction.member',
      many: true,
    }),
    follower: relationship({
      label: '粉絲',
      ref: 'Member.following',
      many: true,
    }),
    following: relationship({
      label: '追蹤中',
      ref: 'Member.follower',
      many: true,
    }),
    block: relationship({
      label: '封鎖',
      ref: 'Member.blocked',
      many: true,
    }),
    blocked: relationship({
      label: '被封鎖',
      ref: 'Member.block',
      many: true,
    }),
    following_category: relationship({
      label: '追蹤分類',
      ref: 'Category',
      many: true,
    }),
    isOfficial: checkbox({
      label: '官方帳號',
      defaultValue: false,
    }),
    status: select({
      label: '帳號狀態',
      type: 'enum',
      options: [
        { label: 'Active', value: 'active' },
        { label: 'Banned', value: 'banned' },
      ],
      defaultValue: 'active',
    }),
    joinDate: timestamp({
      label: '加入日期',
      defaultValue: { kind: 'now' },
    }),
    language: select({
      label: '語系',
      type: 'enum',
      options: [
        { label: '中文', value: 'zh' },
        { label: 'English (英文)', value: 'en' },
        { label: 'Tiếng Việt (越南文)', value: 'vi' },
        { label: 'Bahasa Indonesia (印尼文)', value: 'id' },
        { label: 'ภาษาไทย (泰文)', value: 'th' },
      ],
      defaultValue: 'zh',
    }),
  },
  ui: {
    label: '會員',
    listView: {
      initialColumns: ['name', 'email'],
    },
  },
  access: {
    operation: {
      query: allowRoles(admin, moderator, editor),
      update: allowRoles(admin, moderator),
      create: allowRoles(admin, moderator),
      delete: allowRoles(admin),
    },
  },
  hooks: {
    resolveInput: ({ resolvedData, item }) => {
      const typedItem = item as any
      if (
        typedItem?.is_active === true &&
        resolvedData.is_active === false
      ) {
        resolvedData.email = `inactive: ${typedItem?.email}  ${typedItem?.firebaseId}`
        resolvedData.firebaseId = `inactive: ${typedItem?.firebaseId}`
      } else if (
        typedItem?.is_active === false &&
        resolvedData.is_active === true
      ) {
        const newId = typedItem?.firebaseId?.replace(/^inactive: /, '')
        resolvedData.firebaseId = newId
        resolvedData.email = typedItem?.email
          ?.replace(/^inactive: /, '')
          .replace(`  ${newId}`, '')
      }

      return resolvedData
    },
  },
})

export default utils.addTrackingFields(listConfigurations)
