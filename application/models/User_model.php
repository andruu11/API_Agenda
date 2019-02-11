<?php defined('BASEPATH') OR exit('No direct script access allowed');

class User_Model extends CI_Model{

    protected $user_table = 'usuarios';

    /**
     * User Registration
     * -----------------------------
     * @param: (array) User Data
     */
    public function insert_user(array $data)
    {
        $this->db->insert($this->user_table, $data);
        return $this->db->insert_id();
    }

    
    /**
     * User Fetch
     * -----------------------------
     * @param: (array) User Data
     */
    public function fetch_all_users(){
        $this->db->join('roles', 'usuarios.id_rol = roles.id_rol');
        $query = $this->db->get($this->user_table);
        foreach($query->result() as $row)
        {
            $user_data[] = [
                'usuario' => $row->usuario,
                'email' => $row->email,
                'des_rol' => $row->des_rol,
                'created_at' => $row->created_at,
                'updated_at' => $row->updated_at,
            ];
        }
        return $user_data;
    }

    /**
         * Login User
         * ----------------------
         * @param: user or email
         * @param: paswword
         * ----------------------
         * @method: POST
         * @link: User/login
         */
        public function user_login($usuario, $password)
        {
            $this->db->where('email', $usuario);
            $this->db->or_where('usuario', $usuario);
            $this->db->join('roles', 'usuarios.id_rol = roles.id_rol');
            $q = $this->db->get($this->user_table);
            if ($q->num_rows()) {
                $user_pass = $q->row('password');
                if (sha1(md5($password)) === $user_pass) {
                    return $q->row();
                }
                return FALSE;

            }else {
                return FALSE;
            }
        }
}

?>