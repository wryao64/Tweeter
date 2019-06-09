import React from 'react';
import '../App.css';

class PrivateMessages extends React.Component {
    constructor(props) {
        super(props)

        this.state({
            x: ''
        })
    }

    render() {
        return (
            <div className="PrivateMessages">
                Private Messages
            </div>
        );
    }
}

export default PrivateMessages;
