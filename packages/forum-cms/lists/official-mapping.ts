import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, relationship } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    cmsUser: relationship({
      ref: 'User.officialAccounts',
      many: false,
      label: 'CMS 使用者',
    }),
    officialMember: relationship({
      ref: 'Member',
      many: false,
      label: '前台官方帳號',
    }),
    note: text({ label: '備註' }),
  },
  ui: {
    label: '官方帳號授權',
    listView: {
      initialColumns: ['cmsUser', 'officialMember', 'note'],
    },
  },
  access: {
    operation: {
      query: allowRoles(admin, moderator, editor),
      update: allowRoles(admin),
      create: allowRoles(admin),
      delete: allowRoles(admin),
    },
  },
})

export default utils.addTrackingFields(listConfigurations)
