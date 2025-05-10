export class NotFoundError extends Error {
    constructor() {
        super("not found")
        this.name = new.target.name
    }
}