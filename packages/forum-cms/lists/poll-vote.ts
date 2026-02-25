import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { relationship } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    poll: relationship({
      ref: 'Poll',
      many: false,
      label: '投票活動',
    }),
    option: relationship({
      ref: 'PollOption',
      many: false,
      label: '投票選項',
    }),
    member: relationship({
      ref: 'Member',
      many: false,
      label: '投票會員',
    }),
  },
  ui: {
    label: '投票紀錄',
    listView: {
      initialColumns: ['poll', 'option', 'member'],
    },
  },
  access: {
    operation: {
      query: allowRoles(admin, moderator, editor),
      update: allowRoles(admin),
      create: allowRoles(admin, moderator),
      delete: allowRoles(admin),
    },
  },
})

export default utils.addTrackingFields(listConfigurations)
