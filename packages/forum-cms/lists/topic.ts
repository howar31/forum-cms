import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import { text, integer, relationship, select } from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    name: text({
      validation: { isRequired: true },
      label: '名稱（原文）',
    }),
    language: select({
      label: '原始語言',
      type: 'enum',
      options: [
        { label: '中文', value: 'zh' },
        { label: 'English', value: 'en' },
        { label: 'Tiếng Việt', value: 'vi' },
        { label: 'Bahasa Indonesia', value: 'id' },
        { label: 'ภาษาไทย', value: 'th' },
      ],
    }),
    name_zh: text({ label: '名稱（中文）' }),
    name_en: text({ label: '名稱（英文）' }),
    name_vi: text({ label: '名稱（越南文）' }),
    name_id: text({ label: '名稱（印尼文）' }),
    name_th: text({ label: '名稱（泰文）' }),
    slug: text({
      isIndexed: 'unique',
      validation: { isRequired: true },
      label: '網址代碼',
    }),
    sortOrder: integer({
      label: '排序',
      defaultValue: 0,
    }),
    description: text({
      label: '描述',
      ui: { displayMode: 'textarea' },
    }),
    posts: relationship({
      ref: 'Post.topic',
      many: true,
      label: '文章',
    }),
  },
  ui: {
    label: '主題分類',
    listView: {
      initialColumns: ['name', 'slug', 'sortOrder'],
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
