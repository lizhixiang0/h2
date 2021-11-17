import PropTypes from "prop-types";
import React from "react";
import { connect } from "react-redux";
import { ButtonIcon } from "../../compUI/button";
import Popover from "@material-ui/core/Popover";
import MenuItem from "@material-ui/core/MenuItem";
import { Loading } from "../../compUI";
import {
    isActionFailure,
    isActionInProgress,
    isActionSuccess,
    dateToString,
    resolveAccountURL
} from "../../utils";
import {
    fetchUserNotificationMsgStats,
    readNotificationMessage,
    readNotificationTopXMessages,
    viewUserNotificationMsg,
    clearUserNotificationMsg,
    downloadNotificationAttachment
} from "./actions";
import MessageDetailsDialog from "../../compUI/notification/MessageDetailsDialog";
import AnnouncementDetailsDialog from "../../compUI/notification/AnnouncementDetailsDialog";
import NoNewMessage from "../../compUI/notification/NoNewMessage";
import { GLOBAL_MARKET_ID } from "../../biz/constants";
import { MessageListModes, MessageCategories, getMessageTypeLabelKey, DEFAULT_REFRESH_INTERVAL } from "./";
const ANNOUNCE_CATEGORY =6;

@connect(state => ({
    fetchUserNotificationMsgStatsState: state.fetchUserNotificationMsgStatsReducer,
    market: state.market

}), {
    fetchUserNotificationMsgStats,
    viewUserNotificationMsg,
    readNotificationMessage,
    readNotificationTopXMessages,
    clearUserNotificationMsg,
    downloadNotificationAttachment
})
class NotificationReminder extends React.Component {

    static contextTypes = {
        i18n: PropTypes.object.isRequired,
        router: PropTypes.object.isRequired
    };

    static propTypes = {
        iconColor: PropTypes.string,
        config: PropTypes.object.isRequired,
        color: PropTypes.string,
    };

    state = {
        messageIdList: [],
        showDetailDlg: false,
        resetStartTime: null,
        repeat4NewInterval: 0,
        doneTimes4NewInterval: 0,
        anchorEl: null,
        open: false,
        showAnnouncementPop: true,
    };

    componentDidMount() {
        // for the first time
        this.fetchMessageStats();

        let error = this.props.fetchUserNotificationMsgStatsState.error;
        if (!(error && error.code === 401)) {
            // timer for fetching user messages every 3 minutes
            global.fetchMsgTimer = setInterval(() => this.fetchMessageStats(), DEFAULT_REFRESH_INTERVAL);
        }
    }

    shouldComponentUpdate(nextProps, nextState) {
        // will not update component if request not completed
        if (nextProps.fetchUserNotificationMsgStatsState.stats) {
            return true;
        }
        return false;
    }

    componentWillReceiveProps(nextProps) {
        if ((!isActionSuccess(this.props.fetchUserNotificationMsgStatsState.readMessageActionStatus) && isActionSuccess(nextProps.fetchUserNotificationMsgStatsState.readMessageActionStatus))
            || (!isActionSuccess(this.props.fetchUserNotificationMsgStatsState.readTopXMessageActionStatus) && isActionSuccess(nextProps.fetchUserNotificationMsgStatsState.readTopXMessageActionStatus))
            || (!isActionSuccess(this.props.fetchUserNotificationMsgStatsState.downloadAttachmentActionStatus) && isActionSuccess(nextProps.fetchUserNotificationMsgStatsState.downloadAttachmentActionStatus))
        ) {
            this.fetchMessageStats();
        }

        if ((!isActionSuccess(this.props.fetchUserNotificationMsgStatsState.resetRefreshIntervalActionStatus)
            && isActionSuccess(nextProps.fetchUserNotificationMsgStatsState.resetRefreshIntervalActionStatus))) {

            const newInterval = nextProps.fetchUserNotificationMsgStatsState.newInterval;
            const repeat4NewInterval = nextProps.fetchUserNotificationMsgStatsState.repeat ? nextProps.fetchUserNotificationMsgStatsState.repeat : 0;

            if (!newInterval || !Number.isFinite(newInterval) || !Number.isInteger(newInterval) || (newInterval * 1000 > DEFAULT_REFRESH_INTERVAL)) {
                console.error("Invalid interval:" + newInterval);
                return;
            }

            if (newInterval) {
                let fetchMsgTimer = global.fetchMsgTimer;
                fetchMsgTimer && clearInterval(fetchMsgTimer);
                this.state.resetStartTime = new Date().getTime();
                this.state.repeat4NewInterval = repeat4NewInterval;

                fetchMsgTimer = setInterval(() => {
                    if ((new Date().getTime() - this.state.resetStartTime > DEFAULT_REFRESH_INTERVAL)
                        || (this.state.repeat4NewInterval > 0 && this.state.doneTimes4NewInterval > this.state.repeat4NewInterval)) {
                        clearInterval(fetchMsgTimer);
                        this.state.resetStartTime = null;
                        fetchMsgTimer = setInterval(() => this.fetchMessageStats(), DEFAULT_REFRESH_INTERVAL);
                        return;
                    }

                    if (this.state.repeat4NewInterval > 0) {
                        this.state.doneTimes4NewInterval += 1;
                    }

                    this.fetchMessageStats();
                }, 1000 * newInterval);
            }
        }
    }

    componentWillUnmount() {
        global.fetchMsgTimer && clearInterval(global.fetchMsgTimer);
    }

    fetchMessageStats = (callback) => {
        const { clientId } = this.props.config;
        const marketId = this.props.market.id;
        this.props.fetchUserNotificationMsgStats(clientId, marketId,callback);
    };

    handleReadTopXMessages = () => {
        this.props.readNotificationTopXMessages(this.state.messageIdList);
    };

    handleReadMessage = (e, messageItem) => {
        e.stopPropagation();
        this.props.readNotificationMessage(messageItem.id);
    };

    handleDownloadAttachment = (e, messageItem) => {
        e.stopPropagation();
        this.props.downloadNotificationAttachment(messageItem.id);
    };

    showDetailDlg = msgId => {
        this.props.viewUserNotificationMsg(msgId);
        this.setState({ showDetailDlg: true });
    };

    hideDetailDlg = () => {
        this.setState({ showDetailDlg: false });
        this.props.clearUserNotificationMsg();
        //refresh
        this.fetchMessageStats();
    };

    resolveNotificationUnreadListUrl = () => {
        //#/message/unread?listMode=1&msgCat=0&pageNo=1&pageSize=10
        let ntfUnreadMsgListUrl = resolveAccountURL(this.props.config, "www", true);
        ntfUnreadMsgListUrl += `#/message/unread?listMode=${MessageListModes.UNREAD.key}&msgCat=${MessageCategories.ALL.key}&pageNo=1&pageSize=10`;
        return ntfUnreadMsgListUrl;
    };

    renderTotalUnreadCount(count) {
        return (
            <div className="topmenu_toolbar_router">
                <ButtonIcon
                    onClick={(event) => this.setState({ open: !this.state.open, anchorEl: event.currentTarget })}
                    iconClassName="icon-head-notification"
                    iconSize={20}
                    color={this.props.color}
                >
                </ButtonIcon>
                {(count > 0) && <span className="notification_count_area">{count}</span>}
            </div>
        );
    }

    renderTopXMessages() {
        const { actionStatus, stats } = this.props.fetchUserNotificationMsgStatsState;
        this.state.messageIdList = [];

        if (isActionInProgress(actionStatus)) {
            return <Loading />;
        }

        if (isActionFailure(actionStatus) || !stats || stats.totalCountOfUnread === 0) {
            return <NoNewMessage config={this.props.config} />;
        }

        const { l } = this.context.i18n;
        const unreadMessageList = stats.topXUnreadMessages || [];
        const datalist = [];

        unreadMessageList.map(item => {
            if (item.category !== ANNOUNCE_CATEGORY) {
                this.state.messageIdList.push(item.id);
             }
            datalist.push(
                <MenuItem
                    key={item.id}
                    title={item.title}
                    className={`notification_box_area notification_li_${item.type} ${item.topShown ? "top" : ""}`}
                    onClick={() => {
                        this.showDetailDlg(item.id)
                    }} >
                    <p className="notification_box_tit">{item.title}</p>
                    <em className="notification_box_subtit">{l(getMessageTypeLabelKey(item.type))}<i className="notification_box_line">/</i>{dateToString(item.publishedOn, "YYYY-MM-DD HH:mm:ss")}</em>
                    {// has attachment
                        item.hasAttachment && (
                            <ButtonIcon
                                tooltip={l("tips_ntf_msg_op_download_attachment")}
                                className="notification_area_button"
                                iconClassName="icon-btn-download1"
                                tooltipPosition="top-start"
                                onClick={(e) => this.handleDownloadAttachment(e, item)}>
                            </ButtonIcon>
                        )
                    }
                    {// has no attachment
                        !item.hasAttachment &&item.category !== ANNOUNCE_CATEGORY && (
                            <ButtonIcon
                                tooltip={l("tips_ntf_msg_op_read")}
                                className="notification_area_button"
                                iconClassName="icon-btn-allow"
                                tooltipPosition="top-start"
                                onClick={(e) => this.handleReadMessage(e, item)}>
                            </ButtonIcon>
                        )
                    }
                </MenuItem>

            );
        });
        return (
            datalist
        );
    }

    renderBottomLinks(totalCountOfUnread) {
        const { l } = this.context.i18n;

        if (totalCountOfUnread > 0) {
            return (
                <div className="router_morehalf_area">
                    <MenuItem
                        className="router_more_area "
                        onClick={() => window.open(this.resolveNotificationUnreadListUrl())}
                    >
                        {l("label_ntf_popup_view_all")}
                    </MenuItem>
                    <MenuItem
                        className="router_more_area"
                        onClick={() => this.handleReadTopXMessages()}
                    >
                        {l("label_ntf_popup_mark_as_read")}
                    </MenuItem>
                </div>
            );
        } else {
            return (
                <div
                    className="btn_more_single "
                    onClick={() => window.open(this.resolveNotificationUnreadListUrl())}
                >
                    {l("label_ntf_popup_view_all")}
                </div>
            );
        }
    }

    hideAnnouncementDlg = () => {
        // this.setState({ showAnnouncementPop: false });
        const callback=()=>{
            this.setState({
                showAnnouncementPop: true,
            })
        }
        this.setState({
            showAnnouncementPop: false,
        },()=>{
            this.props.clearUserNotificationMsg();
            this.fetchMessageStats(callback);
        })
    };

    render() {
        const stats = this.props.fetchUserNotificationMsgStatsState.stats;
        const totalCountOfUnread = stats ? stats.totalCountOfUnread : 0;
        const { l } = this.context.i18n;
        const { clientId } = this.props.config;
        const announcementInfos = stats && stats.announcementInfos || [];
        const marketId = this.props.market.id;
        let announcementInfo = {};
        let showPopAnnouncementInfo = false
        // 2，判断市场。1，判断环境
        if (announcementInfos && announcementInfos.length > 0) {
            switch (clientId) {
                case "admin":
                    announcementInfo = announcementInfos.find(item => {
                        if ( item.receiverType && (item.marketId === marketId || item.marketId === GLOBAL_MARKET_ID)) {
                            let arr = item.receiverType.split(",");
                            return (arr.includes("2")||arr.includes("3"))
                        }
                    });
                    break;
                case "developer":
                    announcementInfo = announcementInfos.find(item => {
                        if (item.receiverType && item.marketId === marketId) {
                            let arr = item.receiverType.split(",");
                            return arr.includes("1")
                        }
                    });
                    break;
                default:
                    announcementInfo = null;
                    break;
            }
            if (announcementInfo) {
                showPopAnnouncementInfo = true;
            }
        }
        return (
            <>
                {this.renderTotalUnreadCount(totalCountOfUnread)}
                <Popover
                    open={this.state.open}
                    anchorEl={this.state.anchorEl}
                    onClose={() => this.setState({ displayOthers: false, open: !this.state.open })}
                    anchorOrigin={{
                        vertical: "bottom",
                        horizontal: "center",
                    }}
                    transformOrigin={{
                        vertical: "top",
                        horizontal: "center",
                    }}
                >
                    <div className="notification_con_area">
                        <h3 className="notification_title ">{l("label_ntf_popup_notification")}</h3>
                        {this.renderTopXMessages()}
                        {this.renderBottomLinks(totalCountOfUnread)}
                    </div>

                </Popover>
                <MessageDetailsDialog
                    show={this.state.showDetailDlg}
                    viewMessageState={this.props.fetchUserNotificationMsgStatsState}
                    onHide={this.hideDetailDlg}
                />
                <AnnouncementDetailsDialog
                    show={this.state.showAnnouncementPop && showPopAnnouncementInfo}
                    viewMessageState={this.props.fetchUserNotificationMsgStatsState}
                    onHide={this.hideAnnouncementDlg}
                    announcementInfo={announcementInfo}
                />

            </>

        );
    }
}

export default NotificationReminder;
