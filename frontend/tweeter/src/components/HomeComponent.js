import React from 'react';
import '../App.css';
import OnlineUsers from './OnlineUsers'
import Broadcasts from './Broadcasts'

class HomeComponent extends React.Component {
    // const state = {
    //     authenticated: false
    // };

    // function login(status) {
    //     state.authenticated = status
    // }

    render() {
        return (
            <div className='container'>
                <OnlineUsers className='onlineUsers' />
                <Broadcasts className='broadcasts' />
            </div>
        );
    }
}

export default HomeComponent;
