import { utils } from '@mirrormedia/lilith-core'
import { list } from '@keystone-6/core'
import {
    relationship,
    select,
    timestamp,
} from '@keystone-6/core/fields'

const { allowRoles, admin, moderator, editor } = utils.accessControl

const listConfigurations = list({
    fields: {
        member: relationship({ ref: 'Member.reactions', many: false, label: '會員' }),
        post: relationship({ ref: 'Post.reactions', many: false, label: '文章' }),
        comment: relationship({ ref: 'Comment.reactions', many: false, label: '留言' }),
        emotion: select({
            label: '情緒',
            type: 'enum',
            options: [
                { label: '開心', value: 'happy' },
                { label: '生氣', value: 'angry' },
                { label: '驚訝', value: 'surprise' },
                { label: '傷心', value: 'sad' },
            ],
            validation: { isRequired: true },
        }),
        createdAt: timestamp({
            defaultValue: { kind: 'now' },
            label: '建立時間',
        }),
    },
    ui: {
        label: '反應',
        listView: {
            initialColumns: ['member', 'emotion', 'post', 'comment'],
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
