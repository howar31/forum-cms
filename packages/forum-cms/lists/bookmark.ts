import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { relationship } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    post: relationship({
      ref: 'Post',
      many: false,
      label: '文章',
    }),
    member: relationship({
      ref: 'Member',
      many: false,
      label: '會員',
    }),
  },
  ui: {
    label: '書籤',
    listView: {
      initialColumns: ['post', 'member'],
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
