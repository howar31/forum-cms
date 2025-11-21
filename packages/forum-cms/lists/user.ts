import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'

import {
  text,
  relationship,
  password,
  select,
  checkbox,
  timestamp,
} from '@keystone-6/core/fields'
import { assertPasswordStrength } from '../utils/password-policy'

const { allowRolesForUsers, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
  fields: {
    name: text({
      label: '姓名',
      validation: { isRequired: true },
    }),
    email: text({
      label: 'Email',
      validation: { isRequired: true },
      isIndexed: 'unique',
      isFilterable: true,
    }),
    password: password({
      label: '密碼',
      validation: { isRequired: true },
    }),
    role: select({
      label: '角色權限',
      type: 'string',
      options: [
        {
          label: 'admin',
          value: 'admin',
        },
        {
          label: 'moderator',
          value: 'moderator',
        },
        {
          label: 'editor',
          value: 'editor',
        },
        {
          label: 'contributor',
          value: 'contributor',
        },
      ],
      validation: { isRequired: true },
    }),
    // publisher: relationship({
    //   label: 'Publisher',
    //   ref: 'Publisher.user',
    //   many: false,
    // }),
    isProtected: checkbox({
      label: '受保護',
      defaultValue: false,
    }),
    passwordUpdatedAt: timestamp({
      label: '上次密碼更新時間',
      defaultValue: { kind: 'now' },
      ui: {
        createView: { fieldMode: 'hidden' },
        itemView: { fieldMode: 'read' },
        listView: { fieldMode: 'read' },
      },
    }),
    mustChangePassword: checkbox({
      label: '需要強制變更密碼',
      defaultValue: false,
      ui: {
        description: '勾選後，使用者下次登入會被要求先變更密碼',
      },
    }),
    // posts: relationship({ ref: 'Post.author', many: true }),
  },

  ui: {
    label: '使用者',
    listView: {
      initialColumns: ['name', 'role'],
    },
  },
  access: {
    operation: {
      query: allowRolesForUsers(admin, moderator, editor),
      update: allowRolesForUsers(admin, moderator),
      create: allowRolesForUsers(admin, moderator),
      delete: allowRolesForUsers(admin),
    },
  },
  hooks: {
    resolveInput: async ({ resolvedData, item }) => {
      const data = { ...resolvedData }

      if (typeof data.password === 'string' && data.password.length > 0) {
        assertPasswordStrength(data.password)
        data.passwordUpdatedAt = new Date().toISOString()
        data.mustChangePassword = false
      }

      if (
        typeof data.mustChangePassword === 'undefined' &&
        typeof item?.mustChangePassword !== 'undefined'
      ) {
        data.mustChangePassword = item.mustChangePassword
      }

      return data
    },
  },
})

export default listConfigurations
