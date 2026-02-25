import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, checkbox } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    word: text({
      validation: { isRequired: true },
      isIndexed: 'unique',
      label: '關鍵字',
    }),
    note: text({ label: '備註' }),
    isEnabled: checkbox({
      label: '啟用',
      defaultValue: true,
    }),
  },
  ui: {
    label: '禁用關鍵字',
    listView: {
      initialColumns: ['word', 'isEnabled', 'note'],
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
