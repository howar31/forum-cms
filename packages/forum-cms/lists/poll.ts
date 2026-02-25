import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, integer, relationship, timestamp } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    title: text({
      validation: { isRequired: true },
      label: '標題（原文）',
    }),
    title_zh: text({ label: '標題（中文）' }),
    title_en: text({ label: '標題（英文）' }),
    title_vi: text({ label: '標題（越南文）' }),
    title_id: text({ label: '標題（印尼文）' }),
    title_th: text({ label: '標題（泰文）' }),
    post: relationship({
      ref: 'Post',
      many: false,
      label: '關聯文章',
    }),
    expiresAt: timestamp({
      label: '截止時間',
      db: { isNullable: true },
    }),
    options: relationship({
      ref: 'PollOption.poll',
      many: true,
      label: '投票選項',
    }),
    totalVotes: integer({
      label: '總票數',
      defaultValue: 0,
    }),
  },
  ui: {
    label: '投票活動',
    listView: {
      initialColumns: ['title', 'post', 'totalVotes', 'expiresAt'],
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
})

export default utils.addTrackingFields(listConfigurations)
