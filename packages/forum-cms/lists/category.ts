import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core';
import {
  text,
  integer,
  relationship,
  password,
  timestamp,
  select,
} from '@keystone-6/core/fields';

const {
  allowRoles,
  admin,
  moderator,
  editor,
  owner,
} = utils.accessControl

const listConfigurations = list({
  fields: {
    title: text({ validation: { isRequired: false }, label: '標題' }),
    slug: text({ isIndexed: 'unique', validation: { isRequired: true }, label: '網址代碼' }),
    summary: text({ validation: { isRequired: false }, label: '摘要' }),
    priority: integer({
      label: '排序權重',
      validation: { isRequired: true, min: 0 },
      defaultValue: 0,
    }),
  },
  ui: {
    label: '分類',
    listView: {
      initialColumns: ['title', 'slug'],
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
