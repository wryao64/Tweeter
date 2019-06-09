import React from 'react';
import '../App.css';

class OnlineUsers extends React.Component {
    // const state = {
    //     authenticated: false
    // };

    // function login(status) {
    //     state.authenticated = status
    // }
    getUsers() {
        fetch('http://172.23.159.9:1025/list_users',
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(res => res.json());
    }

    render() {
        return (
            <div className='onlineUsers'>
                <li>1xxxxx</li>
                <li>2xxxxx</li>
                <li>3xxxxx</li>
                <li>4xxxxx</li>
                <li>5xxxxx</li>
                <li>6xxxxx</li>
                <li>7xxxxx</li>
                <li>8xxxxx</li>
                <li>9xxxxx</li>
                <li>10xxxx</li>
            </div>
        );
    }
}

export default OnlineUsers;
