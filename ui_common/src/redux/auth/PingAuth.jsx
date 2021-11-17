import PropTypes from "prop-types";
import React, {Component} from "react";
import {connect} from "react-redux";
import { requireAuthFrountendLogout } from "./actions";
import {removeItem, setItem, getItem, getAndRemoveItem} from "../../utils/storageUtils";

@connect(state => ({
    isAuthenticated: state.auth.isAuthenticated,
    isLogout: state.auth.isLogout,
    isAuthFrontendLogout: state.auth.isAuthFrontendLogout
}))
class PingAuth extends Component {

    static propTypes = {
        authServerUrl: PropTypes.string.isRequired
    };
    state = {
        pingValue:""
    }

    componentDidMount() {
        let that = this
        window.addEventListener("pingValueEvent", function(e) {
            that.setState({pingValue: e.newValue})
        })
    }
    componentWillUnmount() {
        window.removeEventListener("pingValueEvent", ()=>{})
    }
    
    render() {
        if(this.props.isAuthenticated) {
            return (
                <div className="ping_auth_wrap" key={this.state.pingValue}>
                    <embed
                        src={`${this.props.authServerUrl}/ping`}
                        width={0}
                        height={0}
                    />
                </div>
            ); 
        }

        if(requireAuthFrountendLogout()) {
            return (
                <div className="ping_auth_wrap">
                    <embed
                        src={`${this.props.authServerUrl}/frontend_logout`}
                        width={0}
                        height={0}
                    />
                </div>
            );
        }
        return null;
    }
}

export default PingAuth;