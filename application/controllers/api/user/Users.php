<?php defined('BASEPATH') OR exit('No direct script access allowed');

require APPPATH . '/libraries/REST_Controller.php';
 
class Users extends REST_Controller{

    public function __construct()
    {
        parent::__construct();
        $this->load->model('User_Model');
    }
      /**
     * User Register
     * -----------------------
     * @param: usuario
     * @param: email
     * @param: password
     * -----------------------
     * @method: POST
     * @link: Users/register
     */
    public function register_post()
    {
        header("Access-Control-Allow-Origin: *");
         # XSS Filtering
         $data = $this->security->xss_clean($_POST);
         #Form Validation
         $this->form_validation->set_rules('usuario','usuario','trim|required|is_unique[usuarios.usuario]|alpha_numeric',
         array('is_unique' => 'Este usuario ya existe'));
         $this->form_validation->set_rules('email','email','trim|required|is_unique[usuarios.email]|valid_email',
         array('is_unique' => 'Este email ya existe'));
         $this->form_validation->set_rules('password','password','trim|required');
         if ($this->form_validation->run() == FALSE) {
             //Form Validation Errors
             $message = array(
                 'status' => false, 
                 'error' => $this->form_validation->error_array(),
                 'message' => validation_errors() 
             );
             $this->response($message, REST_Controller::HTTP_NOT_FOUND);
         }
         else 
         {
             $insert_data = [
                 'usuario' => $this->input->post('usuario', TRUE),
                 'email' => $this->input->post('email', TRUE),
                 'password' => sha1(md5($this->input->post('password', TRUE))),
                 'id_rol' => $this->input->post('id_rol', TRUE),
                 'created_at' => time(),
                 'updated_at' => time()
             ];
             // Insert user in Database 
             $output = $this->User_Model->insert_user($insert_data);
             if ($output > 0 AND !empty($output)) {
                 //Success 200 Code Send
                 $message = [
                     'status' => true,
                     'message' => "User registrtion successful"
                 ];
                 $this->response($message, REST_Controller::HTTP_OK);
             }else {
                 //Error
                 $message = [
                     'status' => FALSE,
                     'message' => "Not Register Your Account"
                 ];
                 $this->response($message, REST_Controller::HTTP_NOT_FOUND);
             }
         }
    }

    /**
     * Login User
     * -----------------------
     * @method: POST
     * -----------------------
     * @link: Users/login
     */
    public function login_post()
        {
            header("Access-Control-Allow-Origin: *");

            # XSS Filtering (https://www.codeigniter.com/user_guide/libraries/security.html)
            $_POST = $this->security->xss_clean($_POST);
            
            # Form Validation
                $this->form_validation->set_rules('usuario','usuario','trim|required');
                $this->form_validation->set_rules('password','password','trim|required');
            if ($this->form_validation->run() == FALSE)
            {
                // Form Validation Errors
                $message = array(
                    'status' => false,
                    'error' => $this->form_validation->error_array(),
                    'message' => validation_errors()
                );

                $this->response($message, REST_Controller::HTTP_NOT_FOUND);
            }
            else
            {
                // Load Login Function
                $output = $this->User_Model->user_login($this->input->post('usuario'),$this->input->post('password'));
                if (!empty($output) AND $output != FALSE)
                {
                    // Load Authorization Token Library
                    $this->load->library('Authorization_Token');

                    // Generate Token
                    $token_data['id_usuario'] = $output->id_usuario;
                    $token_data['usuario'] = $output->usuario;
                    $token_data['email'] = $output->email;
                    $token_data['des_rol'] = $output->des_rol;
                    $token_data['time'] = time();

                    $user_token = $this->authorization_token->generateToken($token_data);

                    $return_data = [
                        'id_usuario' => $output->id_usuario,
                        'usuario' => $output->usuario,
                        'email' => $output->email,
                        'des_rol' => $output->des_rol,
                        'token' => $user_token,
                    ];

                    // Login Success
                    $message = [
                        'status' => true,
                        'data' => $return_data,
                        'message' => "User login successful"
                    ];
                    $this->response($message, REST_Controller::HTTP_OK);
                } else
                {
                    // Login Error
                    $message = [
                        'status' => FALSE,
                        'message' => "Invalid Username or Password"
                    ];
                    $this->response($message, REST_Controller::HTTP_NOT_FOUND);
                }
            }
        }

    /**
     * Fetch All User Data
     * -----------------------
     * @method: GET
     * -----------------------
     * @link: Users/all
     */
    public function fetch_all_users_get()
    {
        header("Access-Control-Allow-Origin: *");
        $data = $this->User_Model->fetch_all_users();
        $this->response($data);
    }
}

  

?>