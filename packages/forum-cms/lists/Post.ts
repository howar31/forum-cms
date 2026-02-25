import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import {
    text,
    relationship,
    select,
} from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
    fields: {
        title: text({ validation: { isRequired: true }, label: '標題' }),
        content: text({
            label: '原文內容',
            ui: { displayMode: 'textarea' },
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
        ip: text({ label: '發文 IP' }),
        topic: relationship({ ref: 'Topic.posts', many: false, label: '主題分類' }),
        status: select({
            label: '狀態',
            type: 'enum',
            options: [
                { label: 'Published', value: 'published' },
                { label: 'Draft', value: 'draft' },
                { label: 'Archived', value: 'archived' },
                { label: 'Hidden', value: 'hidden' },
            ],
            defaultValue: 'draft',
        }),
        heroImage: relationship({ ref: 'Photo', many: false, label: '主圖' }),
        comments: relationship({ ref: 'Comment.post', many: true, label: '留言' }),
        reactions: relationship({ ref: 'Reaction.post', many: true, label: '反應' }),
        reports: relationship({ ref: 'Report.post', many: true, label: '檢舉紀錄' }),
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
