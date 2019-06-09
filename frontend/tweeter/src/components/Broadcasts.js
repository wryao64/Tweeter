import React from 'react';
import '../App.css';

class Broadcasts extends React.Component {
    getBroadcasts() {
        fetch('http://172.23.159.9:1025/sign_in',
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
            <div className='broadcastForm'>
                <form>
                    <label>
                        Message: <input type="text" name="message" />
                    </label>
                    <input type="submit" value="Submit" />
                </form>
                <div className='card'>
                    Card
                </div>
            </div>
        );
    }
}

export default Broadcasts;
