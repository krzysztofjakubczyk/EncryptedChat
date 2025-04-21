using Client;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;

namespace WpfApp1
{
    class MainViewModel : INotifyPropertyChanged
    {
        public RelayCommand ConnectToServerCommand { get; set; }
        public RelayCommand SendMessageCommand { get; set; }
        private Server _server;
        public ObservableCollection<UserModel> _users { get; set; }
        public ObservableCollection<string> Messages { get; set; }
        public string Username { get; set; }
        public string Message { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;

        public MainViewModel()
        {
            _users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();
            _server = new Server();
            _server.connectedEvent += UserConnected;
            _server.userDisconnectedEvent += RemoveUser;
            _server.messageReceivedEvent += MessageReceived;
            ConnectToServerCommand = new RelayCommand(o => _server.ConnectToServer(Username), o => !string.IsNullOrEmpty(Username));
            SendMessageCommand = new RelayCommand(o => _server.SendMessageToServer(Message), o => !string.IsNullOrEmpty(Message));
        }

        private void RemoveUser()
        {
            var uid = _server._packetReader.ReadMessage();
            var user = _users.Where(x => x.UID == uid).FirstOrDefault();
            Application.Current.Dispatcher.Invoke(() => _users.Remove(user));
        }

        public void MessageReceived(string msg)
        {
            Application.Current.Dispatcher.Invoke(() => Messages.Add(msg));
        }

        private void UserConnected()
        {
            var user = new UserModel
            {
                Username = _server._packetReader.ReadMessage(),
                UID = _server._packetReader.ReadMessage(),
            };
            if (!_users.Any(x => x.UID == user.UID))
            {
                Application.Current.Dispatcher.Invoke(() => _users.Add(user));
                MessageReceived(_users.First().Username + " Dolaczyl do czatu! ");
            }
        }
    }
}
