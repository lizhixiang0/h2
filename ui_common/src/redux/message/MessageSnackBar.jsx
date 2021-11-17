import PropTypes from "prop-types";
import React from "react";
import {connect} from "react-redux";
import Snackbar from "@material-ui/core/Snackbar";
import {messageInitState} from "./initState";
import {reduxGlobalReset} from "../../utils/reduxUtils";
import {getI18nMsgBundle} from "../../ui/i18n/I18nTools";
import Color from "../../styles/Color";

@connect(state => ({
    messageState: state.messageReducer
}), {
    reduxGlobalReset
})
class MessageSnackBar extends React.Component {

    static propTypes = {
        className   : PropTypes.string,
        style       : PropTypes.object,
        messageStyle: PropTypes.object,
    }

    handleSnackbaronRequestClose = () => {

        if (this.props.messageState.callback) {
            this.props.messageState.callback();
        }

        this.props.reduxGlobalReset({
            messageReducer: messageInitState
        })
    }


    render() {
        const {l} = getI18nMsgBundle();

        if (this.props.messageState.message && this.props.messageState.message === "TypeMismatchError") {
            return null
        }

        const {message="",existShowMsg,errtype ,existMsgs={}} = this.props.messageState;
        const {  extMsg1 = "", extMsg2 = "", extMsg3 = "", url = "" } = existMsgs;

        return (
            <Snackbar
                anchorOrigin={ {vertical: "top", horizontal: "center"} }
                open={this.props.messageState.message ? true : false}
                // message={this.props.messageState.message ?
                //     <span style={this.props.messageStyle}>{l(this.props.messageState.message)}</span> : ""}
                message={ 
                    existShowMsg?
                    <>
                       <p>{errtype?l("msg_failed_active_push_task"):l("msg_succeeded_active_push_task") }</p>
                       { extMsg1&&<p style={this.props.messageStyle}>{l(extMsg1)}</p> }
                       { extMsg2&&<p style={this.props.messageStyle}>{l(extMsg2)}</p> }
                       { extMsg3&&<p style={this.props.messageStyle}>{l(extMsg3)}</p> }
                       { url&&<a href={url} target="_blank" style={{color:Color.yellow}}>{l("btn_click_to_pay")}</a> }
                    </>
                    :
                    message?<span style={this.props.messageStyle}>{l(message)}</span> : ""
                 }

                onClose={this.handleSnackbaronRequestClose}
                autoHideDuration={this.props.messageState.autoHide ? 3000 : null}
                className={`${this.props.messageState.className ? this.props.messageState.className : (this.props.className?this.props.className:"")} message_sanck_bar`}
                style={this.props.messageState.style ? {...this.props.messageState.style} : {zIndex:2000, ...this.props.style}}
            />
        );
    }

}

export default MessageSnackBar;