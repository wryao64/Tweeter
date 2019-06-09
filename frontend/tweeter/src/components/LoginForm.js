import React from 'react';

class LoginForm extends React.Component {
    constructor(props) {
        super(props)
        this.state = {
            username: '',
            password: ''
        };

        this.handleUsernameChange = this.handleUsernameChange.bind(this);
        this.handlePasswordChange = this.handlePasswordChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleUsernameChange(event) {
        this.setState({
            username: event.target.value
        });
    }

    handlePasswordChange(event) {
        this.setState({
            password: event.target.value
        });
    }

    handleSubmit(event) {
        // alert('Login attempted by: ' + this.state.username);
        fetch('http://172.23.159.9:1025/sign_in',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: {
                    username: this.state.username,
                    password: this.state.password
                }
            })
        event.preventDefault();
        this.props.login(true)
    }

    render() {
        return (
            <form onSubmit={this.handleSubmit}>
                <label>
                    Username: <input type='text' value={this.state.username} onChange={this.handleUsernameChange} />
                </label>
                <label>
                    Password: <input type='password' value={this.state.password} onChange={this.handlePasswordChange} />
                </label>
                <input type='submit' value='Login' />
            </form>
        );
    }
}

export default LoginForm;