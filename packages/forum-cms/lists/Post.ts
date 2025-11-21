import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import {
    text,
    relationship,
    checkbox,
    timestamp,
} from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
    fields: {
        title: text({ validation: { isRequired: true }, label: '標題' }),
        content_zh: text({
            label: '內容（中文）',
            ui: { displayMode: 'textarea' },
        }),
        content_en: text({
            label: '內容（英文）',
            ui: { displayMode: 'textarea' },
        }),
        content_vi: text({
            label: '內容（越南文）',
            ui: { displayMode: 'textarea' },
        }),
        content_id: text({
            label: '內容（印尼文）',
            ui: { displayMode: 'textarea' },
        }),
        content_th: text({
            label: '內容（泰文）',
            ui: { displayMode: 'textarea' },
        }),
        author: relationship({ ref: 'Member.posts', many: false, label: '作者' }),
        comments: relationship({ ref: 'Comment.post', many: true, label: '留言' }),
        reactions: relationship({ ref: 'Reaction.post', many: true, label: '反應' }),
        is_active: checkbox({
            defaultValue: true,
            label: '啟用',
        }),
        createdAt: timestamp({
            defaultValue: { kind: 'now' },
            label: '建立時間',
        }),
        updatedAt: timestamp({
            db: { updatedAt: true },
            label: '更新時間',
        }),
    },
    ui: {
        label: '文章',
        listView: {
            initialColumns: ['title', 'author', 'createdAt'],
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
