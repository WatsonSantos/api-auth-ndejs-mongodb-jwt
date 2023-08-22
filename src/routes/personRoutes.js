
const router = require('express').Router()

const personController = require('../controllers/personController')


//Rotas
router.get('/', personController.list_all_person);
router.get('/:id', personController.list_all_person);
router.post('/', personController.create_person);
router.patch('/:id', personController.update_person);
router.delete('/:id', personController.delete_person);



module.exports = router