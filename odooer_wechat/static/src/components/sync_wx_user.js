/** @odoo-module **/

import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { listView } from "@web/views/list/list_view";
import { ListController } from "@web/views/list/list_controller";

export class SyncUserController extends ListController {
    setup() {
        super.setup();
        this.orm = useService('orm');
        this.actionService = useService('action');
    }

    async onClickSyncBtn() {
        const action = await this.orm.call(
            "wx.user",
            "action_sync_users"
        );
        window.location.reload();
        // this.actionService.doAction(action)
    }
}

export const SyncUserListView = {
    ...listView,
    Controller: SyncUserController,
    buttonTemplate: "SyncUser.ListView.Buttons",
};

registry.category("views").add("sync_wx_user_tree", SyncUserListView);
