import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, integer, relationship } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    text: text({
      validation: { isRequired: true },
      label: '選項（原文）',
    }),
    text_zh: text({ label: '選項（中文）' }),
    text_en: text({ label: '選項（英文）' }),
    text_vi: text({ label: '選項（越南文）' }),
    text_id: text({ label: '選項（印尼文）' }),
    text_th: text({ label: '選項（泰文）' }),
    poll: relationship({
      ref: 'Poll.options',
      many: false,
      label: '所屬投票',
    }),
    voteCount: integer({
      label: '得票數',
      defaultValue: 0,
    }),
  },
  ui: {
    label: '投票選項',
    listView: {
      initialColumns: ['text', 'poll', 'voteCount'],
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
