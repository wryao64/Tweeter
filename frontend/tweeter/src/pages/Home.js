import React from 'react';
import '../App.css';
import HomeComponent from '../components/HomeComponent'
import LoginForm from '../components/LoginForm';

class Home extends React.Component {
    constructor(props) {
        super(props)

        this.state = {
            authenticated: false
        };

        this.login = this.login.bind(this)
    }

    login(status) {
        this.setState({
            authenticated: status
        });
    }

    render() {
        return (
            <div className="App">
                {this.state.authenticated ? <HomeComponent /> : <LoginForm login={this.login} />}
            </div>
        );
    }
}

export default Home;
