import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { integer, relationship } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    post: relationship({
      ref: 'Post',
      many: false,
      label: '文章',
    }),
    sortOrder: integer({
      label: '顯示順序',
      defaultValue: 0,
    }),
  },
  ui: {
    label: '編輯精選',
    listView: {
      initialColumns: ['post', 'sortOrder'],
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
