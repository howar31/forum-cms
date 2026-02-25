import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, relationship, select } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    post: relationship({
      ref: 'Post.reports',
      many: false,
      label: '檢舉文章',
    }),
    comment: relationship({
      ref: 'Comment.reports',
      many: false,
      label: '檢舉留言',
    }),
    reporter: relationship({
      ref: 'Member',
      many: false,
      label: '檢舉人',
    }),
    ip: text({ label: '檢舉人 IP' }),
    reason: text({
      label: '檢舉原因',
      ui: { displayMode: 'textarea' },
    }),
    status: select({
      label: '處理狀態',
      type: 'enum',
      options: [
        { label: 'Pending', value: 'pending' },
        { label: 'Resolved', value: 'resolved' },
        { label: 'Dismissed', value: 'dismissed' },
      ],
      defaultValue: 'pending',
    }),
    adminNotes: text({
      label: '管理員處理備註',
      ui: { displayMode: 'textarea' },
    }),
  },
  ui: {
    label: '檢舉管理',
    listView: {
      initialColumns: ['reporter', 'post', 'comment', 'reason', 'status'],
    },
  },
  access: {
    operation: {
      query: allowRoles(admin, moderator, editor),
      update: allowRoles(admin, moderator, editor),
      create: allowRoles(admin, moderator, editor),
      delete: allowRoles(admin),
    },
  },
})

export default utils.addTrackingFields(listConfigurations)
